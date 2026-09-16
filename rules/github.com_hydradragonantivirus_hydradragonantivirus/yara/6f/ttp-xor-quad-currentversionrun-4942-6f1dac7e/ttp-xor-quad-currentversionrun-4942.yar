rule TTP_XOR_QUAD_CurrentVersionRun_4942 {
  strings:
    $key_4942 = { 1a 2d [2] 3e 23 [2] 15 0f [2] 3b 2d [2] 2f 36 [2] 20 2c [2] 3e 31 [2] 3c 30 [2] 27 36 [2] 3b 31 [2] 27 1e }

  condition:
    any of them
}