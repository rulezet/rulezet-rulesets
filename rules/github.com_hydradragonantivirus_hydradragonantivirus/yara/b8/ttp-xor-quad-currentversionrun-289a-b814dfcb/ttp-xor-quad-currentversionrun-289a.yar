rule TTP_XOR_QUAD_CurrentVersionRun_289a {
  strings:
    $key_289a = { 7b f5 [2] 5f fb [2] 74 d7 [2] 5a f5 [2] 4e ee [2] 41 f4 [2] 5f e9 [2] 5d e8 [2] 46 ee [2] 5a e9 [2] 46 c6 }

  condition:
    any of them
}