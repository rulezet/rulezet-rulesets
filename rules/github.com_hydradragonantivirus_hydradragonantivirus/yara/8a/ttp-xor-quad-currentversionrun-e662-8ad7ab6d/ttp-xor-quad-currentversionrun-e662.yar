rule TTP_XOR_QUAD_CurrentVersionRun_e662 {
  strings:
    $key_e662 = { b5 0d [2] 91 03 [2] ba 2f [2] 94 0d [2] 80 16 [2] 8f 0c [2] 91 11 [2] 93 10 [2] 88 16 [2] 94 11 [2] 88 3e }

  condition:
    any of them
}