rule TTP_XOR_QUAD_CurrentVersionRun_e60e {
  strings:
    $key_e60e = { b5 61 [2] 91 6f [2] ba 43 [2] 94 61 [2] 80 7a [2] 8f 60 [2] 91 7d [2] 93 7c [2] 88 7a [2] 94 7d [2] 88 52 }

  condition:
    any of them
}