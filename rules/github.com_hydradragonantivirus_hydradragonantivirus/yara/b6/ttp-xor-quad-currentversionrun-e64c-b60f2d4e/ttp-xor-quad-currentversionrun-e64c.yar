rule TTP_XOR_QUAD_CurrentVersionRun_e64c {
  strings:
    $key_e64c = { b5 23 [2] 91 2d [2] ba 01 [2] 94 23 [2] 80 38 [2] 8f 22 [2] 91 3f [2] 93 3e [2] 88 38 [2] 94 3f [2] 88 10 }

  condition:
    any of them
}