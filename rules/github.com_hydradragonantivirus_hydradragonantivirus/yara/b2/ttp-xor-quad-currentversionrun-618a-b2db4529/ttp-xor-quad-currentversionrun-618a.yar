rule TTP_XOR_QUAD_CurrentVersionRun_618a {
  strings:
    $key_618a = { 32 e5 [2] 16 eb [2] 3d c7 [2] 13 e5 [2] 07 fe [2] 08 e4 [2] 16 f9 [2] 14 f8 [2] 0f fe [2] 13 f9 [2] 0f d6 }

  condition:
    any of them
}