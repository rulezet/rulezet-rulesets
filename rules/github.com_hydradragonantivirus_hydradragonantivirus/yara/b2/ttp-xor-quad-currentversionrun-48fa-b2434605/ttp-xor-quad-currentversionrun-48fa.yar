rule TTP_XOR_QUAD_CurrentVersionRun_48fa {
  strings:
    $key_48fa = { 1b 95 [2] 3f 9b [2] 14 b7 [2] 3a 95 [2] 2e 8e [2] 21 94 [2] 3f 89 [2] 3d 88 [2] 26 8e [2] 3a 89 [2] 26 a6 }

  condition:
    any of them
}