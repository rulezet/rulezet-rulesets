rule TTP_XOR_QUAD_CurrentVersionRun_f684 {
  strings:
    $key_f684 = { a5 eb [2] 81 e5 [2] aa c9 [2] 84 eb [2] 90 f0 [2] 9f ea [2] 81 f7 [2] 83 f6 [2] 98 f0 [2] 84 f7 [2] 98 d8 }

  condition:
    any of them
}