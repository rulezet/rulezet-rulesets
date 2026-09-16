rule TTP_XOR_QUAD_CurrentVersionRun_f67c {
  strings:
    $key_f67c = { a5 13 [2] 81 1d [2] aa 31 [2] 84 13 [2] 90 08 [2] 9f 12 [2] 81 0f [2] 83 0e [2] 98 08 [2] 84 0f [2] 98 20 }

  condition:
    any of them
}