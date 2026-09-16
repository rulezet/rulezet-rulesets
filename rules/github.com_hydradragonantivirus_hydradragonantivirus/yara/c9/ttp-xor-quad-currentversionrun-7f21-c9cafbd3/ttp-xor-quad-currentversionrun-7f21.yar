rule TTP_XOR_QUAD_CurrentVersionRun_7f21 {
  strings:
    $key_7f21 = { 2c 4e [2] 08 40 [2] 23 6c [2] 0d 4e [2] 19 55 [2] 16 4f [2] 08 52 [2] 0a 53 [2] 11 55 [2] 0d 52 [2] 11 7d }

  condition:
    any of them
}