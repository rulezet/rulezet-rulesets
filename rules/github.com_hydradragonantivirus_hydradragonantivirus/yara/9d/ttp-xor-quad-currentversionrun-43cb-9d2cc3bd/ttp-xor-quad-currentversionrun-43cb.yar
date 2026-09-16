rule TTP_XOR_QUAD_CurrentVersionRun_43cb {
  strings:
    $key_43cb = { 10 a4 [2] 34 aa [2] 1f 86 [2] 31 a4 [2] 25 bf [2] 2a a5 [2] 34 b8 [2] 36 b9 [2] 2d bf [2] 31 b8 [2] 2d 97 }

  condition:
    any of them
}