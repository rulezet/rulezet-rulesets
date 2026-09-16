rule TTP_XOR_QUAD_CurrentVersionRun_4efd {
  strings:
    $key_4efd = { 1d 92 [2] 39 9c [2] 12 b0 [2] 3c 92 [2] 28 89 [2] 27 93 [2] 39 8e [2] 3b 8f [2] 20 89 [2] 3c 8e [2] 20 a1 }

  condition:
    any of them
}