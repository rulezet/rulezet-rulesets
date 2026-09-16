rule TTP_XOR_QUAD_CurrentVersionRun_f690 {
  strings:
    $key_f690 = { a5 ff [2] 81 f1 [2] aa dd [2] 84 ff [2] 90 e4 [2] 9f fe [2] 81 e3 [2] 83 e2 [2] 98 e4 [2] 84 e3 [2] 98 cc }

  condition:
    any of them
}