rule TTP_XOR_QUAD_CurrentVersionRun_e620 {
  strings:
    $key_e620 = { b5 4f [2] 91 41 [2] ba 6d [2] 94 4f [2] 80 54 [2] 8f 4e [2] 91 53 [2] 93 52 [2] 88 54 [2] 94 53 [2] 88 7c }

  condition:
    any of them
}