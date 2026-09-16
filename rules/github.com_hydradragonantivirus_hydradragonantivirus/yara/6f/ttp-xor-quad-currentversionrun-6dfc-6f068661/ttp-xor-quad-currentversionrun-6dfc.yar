rule TTP_XOR_QUAD_CurrentVersionRun_6dfc {
  strings:
    $key_6dfc = { 3e 93 [2] 1a 9d [2] 31 b1 [2] 1f 93 [2] 0b 88 [2] 04 92 [2] 1a 8f [2] 18 8e [2] 03 88 [2] 1f 8f [2] 03 a0 }

  condition:
    any of them
}