rule TTP_XOR_QUAD_CurrentVersionRun_e62e {
  strings:
    $key_e62e = { b5 41 [2] 91 4f [2] ba 63 [2] 94 41 [2] 80 5a [2] 8f 40 [2] 91 5d [2] 93 5c [2] 88 5a [2] 94 5d [2] 88 72 }

  condition:
    any of them
}