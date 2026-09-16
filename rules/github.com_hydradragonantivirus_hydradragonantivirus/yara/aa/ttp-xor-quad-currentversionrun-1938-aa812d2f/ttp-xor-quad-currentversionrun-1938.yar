rule TTP_XOR_QUAD_CurrentVersionRun_1938 {
  strings:
    $key_1938 = { 4a 57 [2] 6e 59 [2] 45 75 [2] 6b 57 [2] 7f 4c [2] 70 56 [2] 6e 4b [2] 6c 4a [2] 77 4c [2] 6b 4b [2] 77 64 }

  condition:
    any of them
}