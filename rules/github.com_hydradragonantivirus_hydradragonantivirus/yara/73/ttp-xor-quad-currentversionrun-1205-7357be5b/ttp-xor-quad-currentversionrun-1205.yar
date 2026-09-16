rule TTP_XOR_QUAD_CurrentVersionRun_1205 {
  strings:
    $key_1205 = { 41 6a [2] 65 64 [2] 4e 48 [2] 60 6a [2] 74 71 [2] 7b 6b [2] 65 76 [2] 67 77 [2] 7c 71 [2] 60 76 [2] 7c 59 }

  condition:
    any of them
}