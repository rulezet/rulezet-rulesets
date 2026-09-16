rule TTP_XOR_QUAD_CurrentVersionRun_ef8a {
  strings:
    $key_ef8a = { bc e5 [2] 98 eb [2] b3 c7 [2] 9d e5 [2] 89 fe [2] 86 e4 [2] 98 f9 [2] 9a f8 [2] 81 fe [2] 9d f9 [2] 81 d6 }

  condition:
    any of them
}