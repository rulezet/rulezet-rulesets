rule TTP_XOR_QUAD_CurrentVersionRun_ee62 {
  strings:
    $key_ee62 = { bd 0d [2] 99 03 [2] b2 2f [2] 9c 0d [2] 88 16 [2] 87 0c [2] 99 11 [2] 9b 10 [2] 80 16 [2] 9c 11 [2] 80 3e }

  condition:
    any of them
}