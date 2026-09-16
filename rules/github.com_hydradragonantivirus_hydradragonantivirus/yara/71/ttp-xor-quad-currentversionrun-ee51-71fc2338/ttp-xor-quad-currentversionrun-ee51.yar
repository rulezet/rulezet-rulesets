rule TTP_XOR_QUAD_CurrentVersionRun_ee51 {
  strings:
    $key_ee51 = { bd 3e [2] 99 30 [2] b2 1c [2] 9c 3e [2] 88 25 [2] 87 3f [2] 99 22 [2] 9b 23 [2] 80 25 [2] 9c 22 [2] 80 0d }

  condition:
    any of them
}