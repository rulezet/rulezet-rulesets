rule TTP_XOR_QUAD_CurrentVersionRun_f606 {
  strings:
    $key_f606 = { a5 69 [2] 81 67 [2] aa 4b [2] 84 69 [2] 90 72 [2] 9f 68 [2] 81 75 [2] 83 74 [2] 98 72 [2] 84 75 [2] 98 5a }

  condition:
    any of them
}