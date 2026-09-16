rule TTP_XOR_QUAD_CurrentVersionRun_ee47 {
  strings:
    $key_ee47 = { bd 28 [2] 99 26 [2] b2 0a [2] 9c 28 [2] 88 33 [2] 87 29 [2] 99 34 [2] 9b 35 [2] 80 33 [2] 9c 34 [2] 80 1b }

  condition:
    any of them
}