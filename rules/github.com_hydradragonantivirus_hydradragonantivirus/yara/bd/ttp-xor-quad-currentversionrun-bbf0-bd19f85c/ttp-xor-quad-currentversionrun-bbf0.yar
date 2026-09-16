rule TTP_XOR_QUAD_CurrentVersionRun_bbf0 {
  strings:
    $key_bbf0 = { e8 9f [2] cc 91 [2] e7 bd [2] c9 9f [2] dd 84 [2] d2 9e [2] cc 83 [2] ce 82 [2] d5 84 [2] c9 83 [2] d5 ac }

  condition:
    any of them
}