rule TTP_XOR_QUAD_CurrentVersionRun_e88a {
  strings:
    $key_e88a = { bb e5 [2] 9f eb [2] b4 c7 [2] 9a e5 [2] 8e fe [2] 81 e4 [2] 9f f9 [2] 9d f8 [2] 86 fe [2] 9a f9 [2] 86 d6 }

  condition:
    any of them
}