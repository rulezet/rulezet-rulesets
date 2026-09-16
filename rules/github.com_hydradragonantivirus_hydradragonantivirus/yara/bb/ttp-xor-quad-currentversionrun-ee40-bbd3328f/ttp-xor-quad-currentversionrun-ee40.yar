rule TTP_XOR_QUAD_CurrentVersionRun_ee40 {
  strings:
    $key_ee40 = { bd 2f [2] 99 21 [2] b2 0d [2] 9c 2f [2] 88 34 [2] 87 2e [2] 99 33 [2] 9b 32 [2] 80 34 [2] 9c 33 [2] 80 1c }

  condition:
    any of them
}