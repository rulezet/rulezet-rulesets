rule TTP_XOR_QUAD_CurrentVersionRun_f6f6 {
  strings:
    $key_f6f6 = { a5 99 [2] 81 97 [2] aa bb [2] 84 99 [2] 90 82 [2] 9f 98 [2] 81 85 [2] 83 84 [2] 98 82 [2] 84 85 [2] 98 aa }

  condition:
    any of them
}