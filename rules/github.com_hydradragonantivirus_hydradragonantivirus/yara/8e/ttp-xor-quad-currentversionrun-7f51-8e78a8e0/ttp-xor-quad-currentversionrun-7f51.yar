rule TTP_XOR_QUAD_CurrentVersionRun_7f51 {
  strings:
    $key_7f51 = { 2c 3e [2] 08 30 [2] 23 1c [2] 0d 3e [2] 19 25 [2] 16 3f [2] 08 22 [2] 0a 23 [2] 11 25 [2] 0d 22 [2] 11 0d }

  condition:
    any of them
}