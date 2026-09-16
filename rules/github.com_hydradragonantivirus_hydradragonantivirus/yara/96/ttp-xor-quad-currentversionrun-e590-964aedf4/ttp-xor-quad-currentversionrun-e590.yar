rule TTP_XOR_QUAD_CurrentVersionRun_e590 {
  strings:
    $key_e590 = { b6 ff [2] 92 f1 [2] b9 dd [2] 97 ff [2] 83 e4 [2] 8c fe [2] 92 e3 [2] 90 e2 [2] 8b e4 [2] 97 e3 [2] 8b cc }

  condition:
    any of them
}