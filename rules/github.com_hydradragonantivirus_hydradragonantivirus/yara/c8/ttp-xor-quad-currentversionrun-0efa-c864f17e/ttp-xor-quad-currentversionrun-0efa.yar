rule TTP_XOR_QUAD_CurrentVersionRun_0efa {
  strings:
    $key_0efa = { 5d 95 [2] 79 9b [2] 52 b7 [2] 7c 95 [2] 68 8e [2] 67 94 [2] 79 89 [2] 7b 88 [2] 60 8e [2] 7c 89 [2] 60 a6 }

  condition:
    any of them
}