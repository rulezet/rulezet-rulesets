rule TTP_XOR_QUAD_CurrentVersionRun_eef4 {
  strings:
    $key_eef4 = { bd 9b [2] 99 95 [2] b2 b9 [2] 9c 9b [2] 88 80 [2] 87 9a [2] 99 87 [2] 9b 86 [2] 80 80 [2] 9c 87 [2] 80 a8 }

  condition:
    any of them
}