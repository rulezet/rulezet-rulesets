rule TTP_XOR_QUAD_CurrentVersionRun_71e1 {
  strings:
    $key_71e1 = { 22 8e [2] 06 80 [2] 2d ac [2] 03 8e [2] 17 95 [2] 18 8f [2] 06 92 [2] 04 93 [2] 1f 95 [2] 03 92 [2] 1f bd }

  condition:
    any of them
}