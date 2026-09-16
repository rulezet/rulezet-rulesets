rule TTP_XOR_QUAD_CurrentVersionRun_ee41 {
  strings:
    $key_ee41 = { bd 2e [2] 99 20 [2] b2 0c [2] 9c 2e [2] 88 35 [2] 87 2f [2] 99 32 [2] 9b 33 [2] 80 35 [2] 9c 32 [2] 80 1d }

  condition:
    any of them
}