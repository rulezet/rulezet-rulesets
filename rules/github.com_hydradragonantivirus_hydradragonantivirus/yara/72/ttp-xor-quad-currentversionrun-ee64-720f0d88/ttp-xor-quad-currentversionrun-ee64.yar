rule TTP_XOR_QUAD_CurrentVersionRun_ee64 {
  strings:
    $key_ee64 = { bd 0b [2] 99 05 [2] b2 29 [2] 9c 0b [2] 88 10 [2] 87 0a [2] 99 17 [2] 9b 16 [2] 80 10 [2] 9c 17 [2] 80 38 }

  condition:
    any of them
}