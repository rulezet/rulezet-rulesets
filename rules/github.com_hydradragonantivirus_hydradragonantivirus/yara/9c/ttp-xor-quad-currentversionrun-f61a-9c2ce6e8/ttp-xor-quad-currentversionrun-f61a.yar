rule TTP_XOR_QUAD_CurrentVersionRun_f61a {
  strings:
    $key_f61a = { a5 75 [2] 81 7b [2] aa 57 [2] 84 75 [2] 90 6e [2] 9f 74 [2] 81 69 [2] 83 68 [2] 98 6e [2] 84 69 [2] 98 46 }

  condition:
    any of them
}