rule TTP_XOR_QUAD_CurrentVersionRun_4cfd {
  strings:
    $key_4cfd = { 1f 92 [2] 3b 9c [2] 10 b0 [2] 3e 92 [2] 2a 89 [2] 25 93 [2] 3b 8e [2] 39 8f [2] 22 89 [2] 3e 8e [2] 22 a1 }

  condition:
    any of them
}