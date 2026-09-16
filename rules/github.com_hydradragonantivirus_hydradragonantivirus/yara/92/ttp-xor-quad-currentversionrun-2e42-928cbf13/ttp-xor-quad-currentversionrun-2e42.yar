rule TTP_XOR_QUAD_CurrentVersionRun_2e42 {
  strings:
    $key_2e42 = { 7d 2d [2] 59 23 [2] 72 0f [2] 5c 2d [2] 48 36 [2] 47 2c [2] 59 31 [2] 5b 30 [2] 40 36 [2] 5c 31 [2] 40 1e }

  condition:
    any of them
}