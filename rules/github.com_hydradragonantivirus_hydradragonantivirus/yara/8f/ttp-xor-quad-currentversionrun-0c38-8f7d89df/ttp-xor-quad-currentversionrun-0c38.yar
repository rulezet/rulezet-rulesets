rule TTP_XOR_QUAD_CurrentVersionRun_0c38 {
  strings:
    $key_0c38 = { 5f 57 [2] 7b 59 [2] 50 75 [2] 7e 57 [2] 6a 4c [2] 65 56 [2] 7b 4b [2] 79 4a [2] 62 4c [2] 7e 4b [2] 62 64 }

  condition:
    any of them
}