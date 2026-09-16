rule TTP_XOR_QUAD_CurrentVersionRun_4221 {
  strings:
    $key_4221 = { 11 4e [2] 35 40 [2] 1e 6c [2] 30 4e [2] 24 55 [2] 2b 4f [2] 35 52 [2] 37 53 [2] 2c 55 [2] 30 52 [2] 2c 7d }

  condition:
    any of them
}