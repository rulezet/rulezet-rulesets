rule TTP_XOR_QUAD_CurrentVersionRun_3cfd {
  strings:
    $key_3cfd = { 6f 92 [2] 4b 9c [2] 60 b0 [2] 4e 92 [2] 5a 89 [2] 55 93 [2] 4b 8e [2] 49 8f [2] 52 89 [2] 4e 8e [2] 52 a1 }

  condition:
    any of them
}