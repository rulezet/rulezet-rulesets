rule TTP_XOR_QUAD_CurrentVersionRun_6f30 {
  strings:
    $key_6f30 = { 3c 5f [2] 18 51 [2] 33 7d [2] 1d 5f [2] 09 44 [2] 06 5e [2] 18 43 [2] 1a 42 [2] 01 44 [2] 1d 43 [2] 01 6c }

  condition:
    any of them
}