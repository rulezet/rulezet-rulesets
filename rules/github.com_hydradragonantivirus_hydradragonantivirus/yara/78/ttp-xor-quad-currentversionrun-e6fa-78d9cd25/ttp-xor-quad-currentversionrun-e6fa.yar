rule TTP_XOR_QUAD_CurrentVersionRun_e6fa {
  strings:
    $key_e6fa = { b5 95 [2] 91 9b [2] ba b7 [2] 94 95 [2] 80 8e [2] 8f 94 [2] 91 89 [2] 93 88 [2] 88 8e [2] 94 89 [2] 88 a6 }

  condition:
    any of them
}