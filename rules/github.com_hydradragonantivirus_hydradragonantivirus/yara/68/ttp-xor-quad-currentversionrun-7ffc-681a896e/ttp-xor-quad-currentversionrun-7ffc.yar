rule TTP_XOR_QUAD_CurrentVersionRun_7ffc {
  strings:
    $key_7ffc = { 2c 93 [2] 08 9d [2] 23 b1 [2] 0d 93 [2] 19 88 [2] 16 92 [2] 08 8f [2] 0a 8e [2] 11 88 [2] 0d 8f [2] 11 a0 }

  condition:
    any of them
}