rule TTP_XOR_QUAD_CurrentVersionRun_e24c {
  strings:
    $key_e24c = { b1 23 [2] 95 2d [2] be 01 [2] 90 23 [2] 84 38 [2] 8b 22 [2] 95 3f [2] 97 3e [2] 8c 38 [2] 90 3f [2] 8c 10 }

  condition:
    any of them
}