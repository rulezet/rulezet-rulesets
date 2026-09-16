rule TTP_XOR_QUAD_CurrentVersionRun_d428 {
  strings:
    $key_d428 = { 87 47 [2] a3 49 [2] 88 65 [2] a6 47 [2] b2 5c [2] bd 46 [2] a3 5b [2] a1 5a [2] ba 5c [2] a6 5b [2] ba 74 }

  condition:
    any of them
}