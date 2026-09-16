rule TTP_XOR_QUAD_CurrentVersionRun_e609 {
  strings:
    $key_e609 = { b5 66 [2] 91 68 [2] ba 44 [2] 94 66 [2] 80 7d [2] 8f 67 [2] 91 7a [2] 93 7b [2] 88 7d [2] 94 7a [2] 88 55 }

  condition:
    any of them
}