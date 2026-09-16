rule TTP_XOR_QUAD_CurrentVersionRun_e263 {
  strings:
    $key_e263 = { b1 0c [2] 95 02 [2] be 2e [2] 90 0c [2] 84 17 [2] 8b 0d [2] 95 10 [2] 97 11 [2] 8c 17 [2] 90 10 [2] 8c 3f }

  condition:
    any of them
}