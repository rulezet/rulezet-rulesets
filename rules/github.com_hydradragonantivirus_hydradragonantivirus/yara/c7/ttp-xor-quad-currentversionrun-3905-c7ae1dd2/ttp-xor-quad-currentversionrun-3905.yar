rule TTP_XOR_QUAD_CurrentVersionRun_3905 {
  strings:
    $key_3905 = { 6a 6a [2] 4e 64 [2] 65 48 [2] 4b 6a [2] 5f 71 [2] 50 6b [2] 4e 76 [2] 4c 77 [2] 57 71 [2] 4b 76 [2] 57 59 }

  condition:
    any of them
}