rule TTP_XOR_QUAD_CurrentVersionRun_5afa {
  strings:
    $key_5afa = { 09 95 [2] 2d 9b [2] 06 b7 [2] 28 95 [2] 3c 8e [2] 33 94 [2] 2d 89 [2] 2f 88 [2] 34 8e [2] 28 89 [2] 34 a6 }

  condition:
    any of them
}