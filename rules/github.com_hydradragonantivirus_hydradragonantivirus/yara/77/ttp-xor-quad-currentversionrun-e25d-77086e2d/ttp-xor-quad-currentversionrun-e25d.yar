rule TTP_XOR_QUAD_CurrentVersionRun_e25d {
  strings:
    $key_e25d = { b1 32 [2] 95 3c [2] be 10 [2] 90 32 [2] 84 29 [2] 8b 33 [2] 95 2e [2] 97 2f [2] 8c 29 [2] 90 2e [2] 8c 01 }

  condition:
    any of them
}