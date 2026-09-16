rule TTP_XOR_QUAD_CurrentVersionRun_021a {
  strings:
    $key_021a = { 51 75 [2] 75 7b [2] 5e 57 [2] 70 75 [2] 64 6e [2] 6b 74 [2] 75 69 [2] 77 68 [2] 6c 6e [2] 70 69 [2] 6c 46 }

  condition:
    any of them
}