rule TTP_XOR_QUAD_CurrentVersionRun_eee8 {
  strings:
    $key_eee8 = { bd 87 [2] 99 89 [2] b2 a5 [2] 9c 87 [2] 88 9c [2] 87 86 [2] 99 9b [2] 9b 9a [2] 80 9c [2] 9c 9b [2] 80 b4 }

  condition:
    any of them
}