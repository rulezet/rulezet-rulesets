rule TTP_XOR_QUAD_CurrentVersionRun_7efc {
  strings:
    $key_7efc = { 2d 93 [2] 09 9d [2] 22 b1 [2] 0c 93 [2] 18 88 [2] 17 92 [2] 09 8f [2] 0b 8e [2] 10 88 [2] 0c 8f [2] 10 a0 }

  condition:
    any of them
}