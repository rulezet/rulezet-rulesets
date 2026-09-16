rule TTP_XOR_QUAD_CurrentVersionRun_e61a {
  strings:
    $key_e61a = { b5 75 [2] 91 7b [2] ba 57 [2] 94 75 [2] 80 6e [2] 8f 74 [2] 91 69 [2] 93 68 [2] 88 6e [2] 94 69 [2] 88 46 }

  condition:
    any of them
}