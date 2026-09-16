rule TTP_XOR_QUAD_CurrentVersionRun_1005 {
  strings:
    $key_1005 = { 43 6a [2] 67 64 [2] 4c 48 [2] 62 6a [2] 76 71 [2] 79 6b [2] 67 76 [2] 65 77 [2] 7e 71 [2] 62 76 [2] 7e 59 }

  condition:
    any of them
}