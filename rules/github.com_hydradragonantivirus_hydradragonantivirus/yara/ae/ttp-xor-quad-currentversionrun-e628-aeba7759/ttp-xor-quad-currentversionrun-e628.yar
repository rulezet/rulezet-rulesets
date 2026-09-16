rule TTP_XOR_QUAD_CurrentVersionRun_e628 {
  strings:
    $key_e628 = { b5 47 [2] 91 49 [2] ba 65 [2] 94 47 [2] 80 5c [2] 8f 46 [2] 91 5b [2] 93 5a [2] 88 5c [2] 94 5b [2] 88 74 }

  condition:
    any of them
}