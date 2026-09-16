rule TTP_XOR_QUAD_CurrentVersionRun_1afa {
  strings:
    $key_1afa = { 49 95 [2] 6d 9b [2] 46 b7 [2] 68 95 [2] 7c 8e [2] 73 94 [2] 6d 89 [2] 6f 88 [2] 74 8e [2] 68 89 [2] 74 a6 }

  condition:
    any of them
}