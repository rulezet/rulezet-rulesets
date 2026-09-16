rule TTP_XOR_QUAD_CurrentVersionRun_e66a {
  strings:
    $key_e66a = { b5 05 [2] 91 0b [2] ba 27 [2] 94 05 [2] 80 1e [2] 8f 04 [2] 91 19 [2] 93 18 [2] 88 1e [2] 94 19 [2] 88 36 }

  condition:
    any of them
}