rule TTP_XOR_QUAD_CurrentVersionRun_f650 {
  strings:
    $key_f650 = { a5 3f [2] 81 31 [2] aa 1d [2] 84 3f [2] 90 24 [2] 9f 3e [2] 81 23 [2] 83 22 [2] 98 24 [2] 84 23 [2] 98 0c }

  condition:
    any of them
}