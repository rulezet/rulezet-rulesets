rule TTP_XOR_QUAD_CurrentVersionRun_f6a6 {
  strings:
    $key_f6a6 = { a5 c9 [2] 81 c7 [2] aa eb [2] 84 c9 [2] 90 d2 [2] 9f c8 [2] 81 d5 [2] 83 d4 [2] 98 d2 [2] 84 d5 [2] 98 fa }

  condition:
    any of them
}