rule TTP_XOR_QUAD_CurrentVersionRun_ee2c {
  strings:
    $key_ee2c = { bd 43 [2] 99 4d [2] b2 61 [2] 9c 43 [2] 88 58 [2] 87 42 [2] 99 5f [2] 9b 5e [2] 80 58 [2] 9c 5f [2] 80 70 }

  condition:
    any of them
}