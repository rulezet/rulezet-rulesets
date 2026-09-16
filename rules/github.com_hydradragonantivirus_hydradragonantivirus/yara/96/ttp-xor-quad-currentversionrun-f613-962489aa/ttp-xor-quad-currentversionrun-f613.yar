rule TTP_XOR_QUAD_CurrentVersionRun_f613 {
  strings:
    $key_f613 = { a5 7c [2] 81 72 [2] aa 5e [2] 84 7c [2] 90 67 [2] 9f 7d [2] 81 60 [2] 83 61 [2] 98 67 [2] 84 60 [2] 98 4f }

  condition:
    any of them
}