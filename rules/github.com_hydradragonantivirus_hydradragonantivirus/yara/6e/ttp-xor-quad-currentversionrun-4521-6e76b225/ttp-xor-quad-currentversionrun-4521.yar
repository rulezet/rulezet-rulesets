rule TTP_XOR_QUAD_CurrentVersionRun_4521 {
  strings:
    $key_4521 = { 16 4e [2] 32 40 [2] 19 6c [2] 37 4e [2] 23 55 [2] 2c 4f [2] 32 52 [2] 30 53 [2] 2b 55 [2] 37 52 [2] 2b 7d }

  condition:
    any of them
}