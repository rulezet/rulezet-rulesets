rule TTP_XOR_QUAD_CurrentVersionRun_05fa {
  strings:
    $key_05fa = { 56 95 [2] 72 9b [2] 59 b7 [2] 77 95 [2] 63 8e [2] 6c 94 [2] 72 89 [2] 70 88 [2] 6b 8e [2] 77 89 [2] 6b a6 }

  condition:
    any of them
}