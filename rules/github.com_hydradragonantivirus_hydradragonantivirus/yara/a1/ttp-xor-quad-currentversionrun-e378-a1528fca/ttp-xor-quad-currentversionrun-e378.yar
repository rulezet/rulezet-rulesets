rule TTP_XOR_QUAD_CurrentVersionRun_e378 {
  strings:
    $key_e378 = { b0 17 [2] 94 19 [2] bf 35 [2] 91 17 [2] 85 0c [2] 8a 16 [2] 94 0b [2] 96 0a [2] 8d 0c [2] 91 0b [2] 8d 24 }

  condition:
    any of them
}