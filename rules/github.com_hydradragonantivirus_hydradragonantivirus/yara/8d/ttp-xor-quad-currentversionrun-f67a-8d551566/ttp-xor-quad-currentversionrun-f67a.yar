rule TTP_XOR_QUAD_CurrentVersionRun_f67a {
  strings:
    $key_f67a = { a5 15 [2] 81 1b [2] aa 37 [2] 84 15 [2] 90 0e [2] 9f 14 [2] 81 09 [2] 83 08 [2] 98 0e [2] 84 09 [2] 98 26 }

  condition:
    any of them
}