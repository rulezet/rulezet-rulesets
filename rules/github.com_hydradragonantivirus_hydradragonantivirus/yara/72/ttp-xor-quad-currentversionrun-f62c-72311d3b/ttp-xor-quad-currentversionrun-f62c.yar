rule TTP_XOR_QUAD_CurrentVersionRun_f62c {
  strings:
    $key_f62c = { a5 43 [2] 81 4d [2] aa 61 [2] 84 43 [2] 90 58 [2] 9f 42 [2] 81 5f [2] 83 5e [2] 98 58 [2] 84 5f [2] 98 70 }

  condition:
    any of them
}