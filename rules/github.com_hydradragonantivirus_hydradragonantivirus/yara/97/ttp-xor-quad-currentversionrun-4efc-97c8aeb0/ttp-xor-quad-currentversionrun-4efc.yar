rule TTP_XOR_QUAD_CurrentVersionRun_4efc {
  strings:
    $key_4efc = { 1d 93 [2] 39 9d [2] 12 b1 [2] 3c 93 [2] 28 88 [2] 27 92 [2] 39 8f [2] 3b 8e [2] 20 88 [2] 3c 8f [2] 20 a0 }

  condition:
    any of them
}