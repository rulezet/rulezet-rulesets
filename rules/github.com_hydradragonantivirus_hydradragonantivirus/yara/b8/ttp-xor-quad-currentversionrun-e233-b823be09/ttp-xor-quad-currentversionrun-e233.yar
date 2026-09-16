rule TTP_XOR_QUAD_CurrentVersionRun_e233 {
  strings:
    $key_e233 = { b1 5c [2] 95 52 [2] be 7e [2] 90 5c [2] 84 47 [2] 8b 5d [2] 95 40 [2] 97 41 [2] 8c 47 [2] 90 40 [2] 8c 6f }

  condition:
    any of them
}