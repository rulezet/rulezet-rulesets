rule TTP_XOR_QUAD_CurrentVersionRun_11de {
  strings:
    $key_11de = { 42 b1 [2] 66 bf [2] 4d 93 [2] 63 b1 [2] 77 aa [2] 78 b0 [2] 66 ad [2] 64 ac [2] 7f aa [2] 63 ad [2] 7f 82 }

  condition:
    any of them
}