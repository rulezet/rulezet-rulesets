rule TTP_XOR_QUAD_CurrentVersionRun_23fa {
  strings:
    $key_23fa = { 70 95 [2] 54 9b [2] 7f b7 [2] 51 95 [2] 45 8e [2] 4a 94 [2] 54 89 [2] 56 88 [2] 4d 8e [2] 51 89 [2] 4d a6 }

  condition:
    any of them
}