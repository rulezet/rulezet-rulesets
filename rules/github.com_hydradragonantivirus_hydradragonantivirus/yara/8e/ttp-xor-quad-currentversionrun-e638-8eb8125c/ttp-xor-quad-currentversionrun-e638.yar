rule TTP_XOR_QUAD_CurrentVersionRun_e638 {
  strings:
    $key_e638 = { b5 57 [2] 91 59 [2] ba 75 [2] 94 57 [2] 80 4c [2] 8f 56 [2] 91 4b [2] 93 4a [2] 88 4c [2] 94 4b [2] 88 64 }

  condition:
    any of them
}