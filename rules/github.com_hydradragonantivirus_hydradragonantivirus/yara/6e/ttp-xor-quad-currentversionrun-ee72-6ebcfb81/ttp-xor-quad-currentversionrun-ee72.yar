rule TTP_XOR_QUAD_CurrentVersionRun_ee72 {
  strings:
    $key_ee72 = { bd 1d [2] 99 13 [2] b2 3f [2] 9c 1d [2] 88 06 [2] 87 1c [2] 99 01 [2] 9b 00 [2] 80 06 [2] 9c 01 [2] 80 2e }

  condition:
    any of them
}