rule TTP_XOR_QUAD_CurrentVersionRun_0cfd {
  strings:
    $key_0cfd = { 5f 92 [2] 7b 9c [2] 50 b0 [2] 7e 92 [2] 6a 89 [2] 65 93 [2] 7b 8e [2] 79 8f [2] 62 89 [2] 7e 8e [2] 62 a1 }

  condition:
    any of them
}