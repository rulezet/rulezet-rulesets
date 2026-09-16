rule TTP_XOR_QUAD_CurrentVersionRun_f7b1 {
  strings:
    $key_f7b1 = { a4 de [2] 80 d0 [2] ab fc [2] 85 de [2] 91 c5 [2] 9e df [2] 80 c2 [2] 82 c3 [2] 99 c5 [2] 85 c2 [2] 99 ed }

  condition:
    any of them
}