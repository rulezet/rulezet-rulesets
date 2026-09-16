rule TTP_XOR_QUAD_CurrentVersionRun_6901 {
  strings:
    $key_6901 = { 3a 6e [2] 1e 60 [2] 35 4c [2] 1b 6e [2] 0f 75 [2] 00 6f [2] 1e 72 [2] 1c 73 [2] 07 75 [2] 1b 72 [2] 07 5d }

  condition:
    any of them
}