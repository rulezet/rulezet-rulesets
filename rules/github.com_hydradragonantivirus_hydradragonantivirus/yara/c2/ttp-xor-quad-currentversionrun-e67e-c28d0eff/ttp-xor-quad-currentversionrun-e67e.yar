rule TTP_XOR_QUAD_CurrentVersionRun_e67e {
  strings:
    $key_e67e = { b5 11 [2] 91 1f [2] ba 33 [2] 94 11 [2] 80 0a [2] 8f 10 [2] 91 0d [2] 93 0c [2] 88 0a [2] 94 0d [2] 88 22 }

  condition:
    any of them
}