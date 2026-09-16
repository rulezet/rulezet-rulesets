rule TTP_XOR_QUAD_CurrentVersionRun_e605 {
  strings:
    $key_e605 = { b5 6a [2] 91 64 [2] ba 48 [2] 94 6a [2] 80 71 [2] 8f 6b [2] 91 76 [2] 93 77 [2] 88 71 [2] 94 76 [2] 88 59 }

  condition:
    any of them
}