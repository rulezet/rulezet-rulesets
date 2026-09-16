rule TTP_XOR_QUAD_CurrentVersionRun_4551 {
  strings:
    $key_4551 = { 16 3e [2] 32 30 [2] 19 1c [2] 37 3e [2] 23 25 [2] 2c 3f [2] 32 22 [2] 30 23 [2] 2b 25 [2] 37 22 [2] 2b 0d }

  condition:
    any of them
}