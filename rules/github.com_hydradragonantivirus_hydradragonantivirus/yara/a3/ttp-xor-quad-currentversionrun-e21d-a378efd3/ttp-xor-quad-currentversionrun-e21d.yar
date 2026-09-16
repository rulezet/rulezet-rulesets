rule TTP_XOR_QUAD_CurrentVersionRun_e21d {
  strings:
    $key_e21d = { b1 72 [2] 95 7c [2] be 50 [2] 90 72 [2] 84 69 [2] 8b 73 [2] 95 6e [2] 97 6f [2] 8c 69 [2] 90 6e [2] 8c 41 }

  condition:
    any of them
}