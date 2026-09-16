rule TTP_XOR_QUAD_CurrentVersionRun_6ffc {
  strings:
    $key_6ffc = { 3c 93 [2] 18 9d [2] 33 b1 [2] 1d 93 [2] 09 88 [2] 06 92 [2] 18 8f [2] 1a 8e [2] 01 88 [2] 1d 8f [2] 01 a0 }

  condition:
    any of them
}