rule TTP_XOR_QUAD_CurrentVersionRun_e67f {
  strings:
    $key_e67f = { b5 10 [2] 91 1e [2] ba 32 [2] 94 10 [2] 80 0b [2] 8f 11 [2] 91 0c [2] 93 0d [2] 88 0b [2] 94 0c [2] 88 23 }

  condition:
    any of them
}