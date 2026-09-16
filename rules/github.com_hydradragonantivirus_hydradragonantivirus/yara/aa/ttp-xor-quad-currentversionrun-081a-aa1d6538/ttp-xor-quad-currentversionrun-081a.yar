rule TTP_XOR_QUAD_CurrentVersionRun_081a {
  strings:
    $key_081a = { 5b 75 [2] 7f 7b [2] 54 57 [2] 7a 75 [2] 6e 6e [2] 61 74 [2] 7f 69 [2] 7d 68 [2] 66 6e [2] 7a 69 [2] 66 46 }

  condition:
    any of them
}