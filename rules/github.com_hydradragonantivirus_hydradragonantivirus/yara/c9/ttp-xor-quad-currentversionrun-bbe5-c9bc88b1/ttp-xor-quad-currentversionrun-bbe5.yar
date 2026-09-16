rule TTP_XOR_QUAD_CurrentVersionRun_bbe5 {
  strings:
    $key_bbe5 = { e8 8a [2] cc 84 [2] e7 a8 [2] c9 8a [2] dd 91 [2] d2 8b [2] cc 96 [2] ce 97 [2] d5 91 [2] c9 96 [2] d5 b9 }

  condition:
    any of them
}