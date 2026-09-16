rule TTP_XOR_QUAD_CurrentVersionRun_24ed {
  strings:
    $key_24ed = { 77 82 [2] 53 8c [2] 78 a0 [2] 56 82 [2] 42 99 [2] 4d 83 [2] 53 9e [2] 51 9f [2] 4a 99 [2] 56 9e [2] 4a b1 }

  condition:
    any of them
}