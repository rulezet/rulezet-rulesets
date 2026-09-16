rule TTP_XOR_QUAD_CurrentVersionRun_6ffd {
  strings:
    $key_6ffd = { 3c 92 [2] 18 9c [2] 33 b0 [2] 1d 92 [2] 09 89 [2] 06 93 [2] 18 8e [2] 1a 8f [2] 01 89 [2] 1d 8e [2] 01 a1 }

  condition:
    any of them
}