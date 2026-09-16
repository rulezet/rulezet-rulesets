rule TTP_XOR_QUAD_CurrentVersionRun_2890 {
  strings:
    $key_2890 = { 7b ff [2] 5f f1 [2] 74 dd [2] 5a ff [2] 4e e4 [2] 41 fe [2] 5f e3 [2] 5d e2 [2] 46 e4 [2] 5a e3 [2] 46 cc }

  condition:
    any of them
}