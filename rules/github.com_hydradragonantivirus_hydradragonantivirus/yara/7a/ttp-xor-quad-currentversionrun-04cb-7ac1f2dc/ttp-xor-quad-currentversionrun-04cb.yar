rule TTP_XOR_QUAD_CurrentVersionRun_04cb {
  strings:
    $key_04cb = { 57 a4 [2] 73 aa [2] 58 86 [2] 76 a4 [2] 62 bf [2] 6d a5 [2] 73 b8 [2] 71 b9 [2] 6a bf [2] 76 b8 [2] 6a 97 }

  condition:
    any of them
}