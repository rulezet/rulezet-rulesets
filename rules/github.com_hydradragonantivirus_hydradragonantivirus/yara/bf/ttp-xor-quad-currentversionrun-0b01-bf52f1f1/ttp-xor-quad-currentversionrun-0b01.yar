rule TTP_XOR_QUAD_CurrentVersionRun_0b01 {
  strings:
    $key_0b01 = { 58 6e [2] 7c 60 [2] 57 4c [2] 79 6e [2] 6d 75 [2] 62 6f [2] 7c 72 [2] 7e 73 [2] 65 75 [2] 79 72 [2] 65 5d }

  condition:
    any of them
}