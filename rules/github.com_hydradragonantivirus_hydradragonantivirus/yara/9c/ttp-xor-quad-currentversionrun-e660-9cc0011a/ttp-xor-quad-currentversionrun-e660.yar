rule TTP_XOR_QUAD_CurrentVersionRun_e660 {
  strings:
    $key_e660 = { b5 0f [2] 91 01 [2] ba 2d [2] 94 0f [2] 80 14 [2] 8f 0e [2] 91 13 [2] 93 12 [2] 88 14 [2] 94 13 [2] 88 3c }

  condition:
    any of them
}