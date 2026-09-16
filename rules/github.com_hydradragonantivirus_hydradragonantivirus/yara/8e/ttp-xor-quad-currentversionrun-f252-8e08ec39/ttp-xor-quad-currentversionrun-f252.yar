rule TTP_XOR_QUAD_CurrentVersionRun_f252 {
  strings:
    $key_f252 = { a1 3d [2] 85 33 [2] ae 1f [2] 80 3d [2] 94 26 [2] 9b 3c [2] 85 21 [2] 87 20 [2] 9c 26 [2] 80 21 [2] 9c 0e }

  condition:
    any of them
}