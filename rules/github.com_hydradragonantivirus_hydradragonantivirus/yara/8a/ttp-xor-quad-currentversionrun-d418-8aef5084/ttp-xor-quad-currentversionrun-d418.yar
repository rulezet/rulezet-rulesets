rule TTP_XOR_QUAD_CurrentVersionRun_d418 {
  strings:
    $key_d418 = { 87 77 [2] a3 79 [2] 88 55 [2] a6 77 [2] b2 6c [2] bd 76 [2] a3 6b [2] a1 6a [2] ba 6c [2] a6 6b [2] ba 44 }

  condition:
    any of them
}