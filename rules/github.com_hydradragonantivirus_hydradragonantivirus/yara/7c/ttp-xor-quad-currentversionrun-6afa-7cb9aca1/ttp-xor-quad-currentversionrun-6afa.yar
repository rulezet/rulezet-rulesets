rule TTP_XOR_QUAD_CurrentVersionRun_6afa {
  strings:
    $key_6afa = { 39 95 [2] 1d 9b [2] 36 b7 [2] 18 95 [2] 0c 8e [2] 03 94 [2] 1d 89 [2] 1f 88 [2] 04 8e [2] 18 89 [2] 04 a6 }

  condition:
    any of them
}