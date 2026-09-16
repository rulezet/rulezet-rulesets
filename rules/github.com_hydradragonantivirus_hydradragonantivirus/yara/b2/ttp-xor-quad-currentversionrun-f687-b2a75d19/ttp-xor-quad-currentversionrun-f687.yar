rule TTP_XOR_QUAD_CurrentVersionRun_f687 {
  strings:
    $key_f687 = { a5 e8 [2] 81 e6 [2] aa ca [2] 84 e8 [2] 90 f3 [2] 9f e9 [2] 81 f4 [2] 83 f5 [2] 98 f3 [2] 84 f4 [2] 98 db }

  condition:
    any of them
}