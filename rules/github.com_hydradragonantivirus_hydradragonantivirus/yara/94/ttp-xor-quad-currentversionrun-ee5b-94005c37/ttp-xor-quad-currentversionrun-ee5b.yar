rule TTP_XOR_QUAD_CurrentVersionRun_ee5b {
  strings:
    $key_ee5b = { bd 34 [2] 99 3a [2] b2 16 [2] 9c 34 [2] 88 2f [2] 87 35 [2] 99 28 [2] 9b 29 [2] 80 2f [2] 9c 28 [2] 80 07 }

  condition:
    any of them
}