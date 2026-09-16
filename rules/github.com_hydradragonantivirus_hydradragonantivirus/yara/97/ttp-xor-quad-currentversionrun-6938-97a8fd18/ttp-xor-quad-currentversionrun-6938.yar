rule TTP_XOR_QUAD_CurrentVersionRun_6938 {
  strings:
    $key_6938 = { 3a 57 [2] 1e 59 [2] 35 75 [2] 1b 57 [2] 0f 4c [2] 00 56 [2] 1e 4b [2] 1c 4a [2] 07 4c [2] 1b 4b [2] 07 64 }

  condition:
    any of them
}