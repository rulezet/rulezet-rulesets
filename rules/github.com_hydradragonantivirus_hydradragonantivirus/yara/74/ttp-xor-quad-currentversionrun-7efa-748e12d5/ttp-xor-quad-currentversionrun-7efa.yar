rule TTP_XOR_QUAD_CurrentVersionRun_7efa {
  strings:
    $key_7efa = { 2d 95 [2] 09 9b [2] 22 b7 [2] 0c 95 [2] 18 8e [2] 17 94 [2] 09 89 [2] 0b 88 [2] 10 8e [2] 0c 89 [2] 10 a6 }

  condition:
    any of them
}