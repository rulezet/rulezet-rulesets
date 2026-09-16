rule TTP_XOR_QUAD_CurrentVersionRun_ee79 {
  strings:
    $key_ee79 = { bd 16 [2] 99 18 [2] b2 34 [2] 9c 16 [2] 88 0d [2] 87 17 [2] 99 0a [2] 9b 0b [2] 80 0d [2] 9c 0a [2] 80 25 }

  condition:
    any of them
}