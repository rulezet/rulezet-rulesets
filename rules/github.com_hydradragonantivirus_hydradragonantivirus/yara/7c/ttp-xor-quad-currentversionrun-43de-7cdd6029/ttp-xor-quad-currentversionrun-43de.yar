rule TTP_XOR_QUAD_CurrentVersionRun_43de {
  strings:
    $key_43de = { 10 b1 [2] 34 bf [2] 1f 93 [2] 31 b1 [2] 25 aa [2] 2a b0 [2] 34 ad [2] 36 ac [2] 2d aa [2] 31 ad [2] 2d 82 }

  condition:
    any of them
}