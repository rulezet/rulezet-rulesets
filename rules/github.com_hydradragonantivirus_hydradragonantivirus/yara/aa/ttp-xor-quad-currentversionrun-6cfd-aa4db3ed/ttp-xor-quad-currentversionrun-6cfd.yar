rule TTP_XOR_QUAD_CurrentVersionRun_6cfd {
  strings:
    $key_6cfd = { 3f 92 [2] 1b 9c [2] 30 b0 [2] 1e 92 [2] 0a 89 [2] 05 93 [2] 1b 8e [2] 19 8f [2] 02 89 [2] 1e 8e [2] 02 a1 }

  condition:
    any of them
}