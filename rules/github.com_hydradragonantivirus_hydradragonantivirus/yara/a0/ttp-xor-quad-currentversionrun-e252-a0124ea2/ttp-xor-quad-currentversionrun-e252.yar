rule TTP_XOR_QUAD_CurrentVersionRun_e252 {
  strings:
    $key_e252 = { b1 3d [2] 95 33 [2] be 1f [2] 90 3d [2] 84 26 [2] 8b 3c [2] 95 21 [2] 97 20 [2] 8c 26 [2] 90 21 [2] 8c 0e }

  condition:
    any of them
}