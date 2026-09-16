rule TTP_XOR_QUAD_CurrentVersionRun_f65d {
  strings:
    $key_f65d = { a5 32 [2] 81 3c [2] aa 10 [2] 84 32 [2] 90 29 [2] 9f 33 [2] 81 2e [2] 83 2f [2] 98 29 [2] 84 2e [2] 98 01 }

  condition:
    any of them
}