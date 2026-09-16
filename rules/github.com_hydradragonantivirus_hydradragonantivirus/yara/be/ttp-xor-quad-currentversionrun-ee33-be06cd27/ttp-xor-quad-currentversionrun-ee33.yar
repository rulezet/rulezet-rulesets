rule TTP_XOR_QUAD_CurrentVersionRun_ee33 {
  strings:
    $key_ee33 = { bd 5c [2] 99 52 [2] b2 7e [2] 9c 5c [2] 88 47 [2] 87 5d [2] 99 40 [2] 9b 41 [2] 80 47 [2] 9c 40 [2] 80 6f }

  condition:
    any of them
}