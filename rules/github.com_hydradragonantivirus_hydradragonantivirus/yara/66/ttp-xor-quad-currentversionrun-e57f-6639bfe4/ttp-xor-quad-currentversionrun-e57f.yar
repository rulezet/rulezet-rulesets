rule TTP_XOR_QUAD_CurrentVersionRun_e57f {
  strings:
    $key_e57f = { b6 10 [2] 92 1e [2] b9 32 [2] 97 10 [2] 83 0b [2] 8c 11 [2] 92 0c [2] 90 0d [2] 8b 0b [2] 97 0c [2] 8b 23 }

  condition:
    any of them
}