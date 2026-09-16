rule TTP_XOR_QUAD_CurrentVersionRun_f8fa {
  strings:
    $key_f8fa = { ab 95 [2] 8f 9b [2] a4 b7 [2] 8a 95 [2] 9e 8e [2] 91 94 [2] 8f 89 [2] 8d 88 [2] 96 8e [2] 8a 89 [2] 96 a6 }

  condition:
    any of them
}