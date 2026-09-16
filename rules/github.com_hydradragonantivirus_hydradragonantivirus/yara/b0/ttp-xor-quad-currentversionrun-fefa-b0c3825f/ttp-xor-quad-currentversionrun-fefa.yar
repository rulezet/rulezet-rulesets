rule TTP_XOR_QUAD_CurrentVersionRun_fefa {
  strings:
    $key_fefa = { ad 95 [2] 89 9b [2] a2 b7 [2] 8c 95 [2] 98 8e [2] 97 94 [2] 89 89 [2] 8b 88 [2] 90 8e [2] 8c 89 [2] 90 a6 }

  condition:
    any of them
}