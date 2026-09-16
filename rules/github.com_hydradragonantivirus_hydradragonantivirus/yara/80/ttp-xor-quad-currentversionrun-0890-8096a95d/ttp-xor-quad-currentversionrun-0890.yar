rule TTP_XOR_QUAD_CurrentVersionRun_0890 {
  strings:
    $key_0890 = { 5b ff [2] 7f f1 [2] 54 dd [2] 7a ff [2] 6e e4 [2] 61 fe [2] 7f e3 [2] 7d e2 [2] 66 e4 [2] 7a e3 [2] 66 cc }

  condition:
    any of them
}