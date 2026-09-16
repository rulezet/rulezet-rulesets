rule TTP_XOR_QUAD_CurrentVersionRun_4f30 {
  strings:
    $key_4f30 = { 1c 5f [2] 38 51 [2] 13 7d [2] 3d 5f [2] 29 44 [2] 26 5e [2] 38 43 [2] 3a 42 [2] 21 44 [2] 3d 43 [2] 21 6c }

  condition:
    any of them
}