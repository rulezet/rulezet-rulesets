rule TTP_XOR_QUAD_CurrentVersionRun_5efc {
  strings:
    $key_5efc = { 0d 93 [2] 29 9d [2] 02 b1 [2] 2c 93 [2] 38 88 [2] 37 92 [2] 29 8f [2] 2b 8e [2] 30 88 [2] 2c 8f [2] 30 a0 }

  condition:
    any of them
}