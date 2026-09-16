rule TTP_XOR_QUAD_CurrentVersionRun_d4e5 {
  strings:
    $key_d4e5 = { 87 8a [2] a3 84 [2] 88 a8 [2] a6 8a [2] b2 91 [2] bd 8b [2] a3 96 [2] a1 97 [2] ba 91 [2] a6 96 [2] ba b9 }

  condition:
    any of them
}