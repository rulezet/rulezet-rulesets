rule TTP_XOR_QUAD_CurrentVersionRun_06fa {
  strings:
    $key_06fa = { 55 95 [2] 71 9b [2] 5a b7 [2] 74 95 [2] 60 8e [2] 6f 94 [2] 71 89 [2] 73 88 [2] 68 8e [2] 74 89 [2] 68 a6 }

  condition:
    any of them
}