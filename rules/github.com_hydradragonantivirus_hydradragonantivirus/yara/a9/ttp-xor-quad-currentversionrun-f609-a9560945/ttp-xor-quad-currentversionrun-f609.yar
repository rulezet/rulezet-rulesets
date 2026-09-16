rule TTP_XOR_QUAD_CurrentVersionRun_f609 {
  strings:
    $key_f609 = { a5 66 [2] 81 68 [2] aa 44 [2] 84 66 [2] 90 7d [2] 9f 67 [2] 81 7a [2] 83 7b [2] 98 7d [2] 84 7a [2] 98 55 }

  condition:
    any of them
}