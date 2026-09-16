rule TTP_XOR_QUAD_CurrentVersionRun_ee50 {
  strings:
    $key_ee50 = { bd 3f [2] 99 31 [2] b2 1d [2] 9c 3f [2] 88 24 [2] 87 3e [2] 99 23 [2] 9b 22 [2] 80 24 [2] 9c 23 [2] 80 0c }

  condition:
    any of them
}