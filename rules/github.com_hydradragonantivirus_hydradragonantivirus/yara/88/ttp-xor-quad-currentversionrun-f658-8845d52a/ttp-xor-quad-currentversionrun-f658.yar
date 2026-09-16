rule TTP_XOR_QUAD_CurrentVersionRun_f658 {
  strings:
    $key_f658 = { a5 37 [2] 81 39 [2] aa 15 [2] 84 37 [2] 90 2c [2] 9f 36 [2] 81 2b [2] 83 2a [2] 98 2c [2] 84 2b [2] 98 04 }

  condition:
    any of them
}