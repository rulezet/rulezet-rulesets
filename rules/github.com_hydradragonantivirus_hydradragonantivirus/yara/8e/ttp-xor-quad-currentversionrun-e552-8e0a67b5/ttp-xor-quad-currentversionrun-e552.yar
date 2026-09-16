rule TTP_XOR_QUAD_CurrentVersionRun_e552 {
  strings:
    $key_e552 = { b6 3d [2] 92 33 [2] b9 1f [2] 97 3d [2] 83 26 [2] 8c 3c [2] 92 21 [2] 90 20 [2] 8b 26 [2] 97 21 [2] 8b 0e }

  condition:
    any of them
}