rule TTP_XOR_QUAD_CurrentVersionRun_ee56 {
  strings:
    $key_ee56 = { bd 39 [2] 99 37 [2] b2 1b [2] 9c 39 [2] 88 22 [2] 87 38 [2] 99 25 [2] 9b 24 [2] 80 22 [2] 9c 25 [2] 80 0a }

  condition:
    any of them
}