rule TTP_XOR_QUAD_CurrentVersionRun_e66e {
  strings:
    $key_e66e = { b5 01 [2] 91 0f [2] ba 23 [2] 94 01 [2] 80 1a [2] 8f 00 [2] 91 1d [2] 93 1c [2] 88 1a [2] 94 1d [2] 88 32 }

  condition:
    any of them
}