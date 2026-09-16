rule TTP_XOR_QUAD_CurrentVersionRun_f61b {
  strings:
    $key_f61b = { a5 74 [2] 81 7a [2] aa 56 [2] 84 74 [2] 90 6f [2] 9f 75 [2] 81 68 [2] 83 69 [2] 98 6f [2] 84 68 [2] 98 47 }

  condition:
    any of them
}