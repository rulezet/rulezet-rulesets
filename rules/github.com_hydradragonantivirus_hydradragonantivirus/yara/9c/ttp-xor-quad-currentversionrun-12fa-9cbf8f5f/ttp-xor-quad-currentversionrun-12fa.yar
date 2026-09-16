rule TTP_XOR_QUAD_CurrentVersionRun_12fa {
  strings:
    $key_12fa = { 41 95 [2] 65 9b [2] 4e b7 [2] 60 95 [2] 74 8e [2] 7b 94 [2] 65 89 [2] 67 88 [2] 7c 8e [2] 60 89 [2] 7c a6 }

  condition:
    any of them
}