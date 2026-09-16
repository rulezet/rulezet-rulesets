rule TTP_XOR_QUAD_CurrentVersionRun_e607 {
  strings:
    $key_e607 = { b5 68 [2] 91 66 [2] ba 4a [2] 94 68 [2] 80 73 [2] 8f 69 [2] 91 74 [2] 93 75 [2] 88 73 [2] 94 74 [2] 88 5b }

  condition:
    any of them
}