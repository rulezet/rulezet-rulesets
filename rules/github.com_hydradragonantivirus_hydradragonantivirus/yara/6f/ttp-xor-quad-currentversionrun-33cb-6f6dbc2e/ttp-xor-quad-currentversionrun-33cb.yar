rule TTP_XOR_QUAD_CurrentVersionRun_33cb {
  strings:
    $key_33cb = { 60 a4 [2] 44 aa [2] 6f 86 [2] 41 a4 [2] 55 bf [2] 5a a5 [2] 44 b8 [2] 46 b9 [2] 5d bf [2] 41 b8 [2] 5d 97 }

  condition:
    any of them
}