rule TTP_XOR_QUAD_CurrentVersionRun_03cb {
  strings:
    $key_03cb = { 50 a4 [2] 74 aa [2] 5f 86 [2] 71 a4 [2] 65 bf [2] 6a a5 [2] 74 b8 [2] 76 b9 [2] 6d bf [2] 71 b8 [2] 6d 97 }

  condition:
    any of them
}