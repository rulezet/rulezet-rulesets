rule TTP_XOR_QUAD_CurrentVersionRun_ee63 {
  strings:
    $key_ee63 = { bd 0c [2] 99 02 [2] b2 2e [2] 9c 0c [2] 88 17 [2] 87 0d [2] 99 10 [2] 9b 11 [2] 80 17 [2] 9c 10 [2] 80 3f }

  condition:
    any of them
}