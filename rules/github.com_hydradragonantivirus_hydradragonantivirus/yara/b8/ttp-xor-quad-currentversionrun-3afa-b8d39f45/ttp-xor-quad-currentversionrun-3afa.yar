rule TTP_XOR_QUAD_CurrentVersionRun_3afa {
  strings:
    $key_3afa = { 69 95 [2] 4d 9b [2] 66 b7 [2] 48 95 [2] 5c 8e [2] 53 94 [2] 4d 89 [2] 4f 88 [2] 54 8e [2] 48 89 [2] 54 a6 }

  condition:
    any of them
}