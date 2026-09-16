rule TTP_XOR_QUAD_CurrentVersionRun_ee36 {
  strings:
    $key_ee36 = { bd 59 [2] 99 57 [2] b2 7b [2] 9c 59 [2] 88 42 [2] 87 58 [2] 99 45 [2] 9b 44 [2] 80 42 [2] 9c 45 [2] 80 6a }

  condition:
    any of them
}