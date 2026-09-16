rule TTP_XOR_QUAD_CurrentVersionRun_f62a {
  strings:
    $key_f62a = { a5 45 [2] 81 4b [2] aa 67 [2] 84 45 [2] 90 5e [2] 9f 44 [2] 81 59 [2] 83 58 [2] 98 5e [2] 84 59 [2] 98 76 }

  condition:
    any of them
}