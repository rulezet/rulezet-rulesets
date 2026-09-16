rule TTP_XOR_QUAD_CurrentVersionRun_11fa {
  strings:
    $key_11fa = { 42 95 [2] 66 9b [2] 4d b7 [2] 63 95 [2] 77 8e [2] 78 94 [2] 66 89 [2] 64 88 [2] 7f 8e [2] 63 89 [2] 7f a6 }

  condition:
    any of them
}