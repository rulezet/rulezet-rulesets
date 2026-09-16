rule TTP_XOR_QUAD_CurrentVersionRun_d948 {
  strings:
    $key_d948 = { 8a 27 [2] ae 29 [2] 85 05 [2] ab 27 [2] bf 3c [2] b0 26 [2] ae 3b [2] ac 3a [2] b7 3c [2] ab 3b [2] b7 14 }

  condition:
    any of them
}