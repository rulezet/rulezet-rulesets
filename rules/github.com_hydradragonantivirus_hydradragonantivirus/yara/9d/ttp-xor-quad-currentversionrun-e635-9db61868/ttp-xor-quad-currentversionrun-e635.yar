rule TTP_XOR_QUAD_CurrentVersionRun_e635 {
  strings:
    $key_e635 = { b5 5a [2] 91 54 [2] ba 78 [2] 94 5a [2] 80 41 [2] 8f 5b [2] 91 46 [2] 93 47 [2] 88 41 [2] 94 46 [2] 88 69 }

  condition:
    any of them
}