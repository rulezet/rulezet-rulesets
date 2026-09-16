rule TTP_XOR_QUAD_CurrentVersionRun_f6f7 {
  strings:
    $key_f6f7 = { a5 98 [2] 81 96 [2] aa ba [2] 84 98 [2] 90 83 [2] 9f 99 [2] 81 84 [2] 83 85 [2] 98 83 [2] 84 84 [2] 98 ab }

  condition:
    any of them
}