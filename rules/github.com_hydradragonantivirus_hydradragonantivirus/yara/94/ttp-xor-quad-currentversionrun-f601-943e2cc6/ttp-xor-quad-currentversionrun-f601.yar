rule TTP_XOR_QUAD_CurrentVersionRun_f601 {
  strings:
    $key_f601 = { a5 6e [2] 81 60 [2] aa 4c [2] 84 6e [2] 90 75 [2] 9f 6f [2] 81 72 [2] 83 73 [2] 98 75 [2] 84 72 [2] 98 5d }

  condition:
    any of them
}