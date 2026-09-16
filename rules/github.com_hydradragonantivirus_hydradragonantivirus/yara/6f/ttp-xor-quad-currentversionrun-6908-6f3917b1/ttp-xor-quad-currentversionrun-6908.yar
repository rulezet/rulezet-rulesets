rule TTP_XOR_QUAD_CurrentVersionRun_6908 {
  strings:
    $key_6908 = { 3a 67 [2] 1e 69 [2] 35 45 [2] 1b 67 [2] 0f 7c [2] 00 66 [2] 1e 7b [2] 1c 7a [2] 07 7c [2] 1b 7b [2] 07 54 }

  condition:
    any of them
}