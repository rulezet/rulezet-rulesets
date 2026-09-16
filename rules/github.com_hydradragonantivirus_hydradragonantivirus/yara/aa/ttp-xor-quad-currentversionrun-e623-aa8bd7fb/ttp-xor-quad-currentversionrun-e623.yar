rule TTP_XOR_QUAD_CurrentVersionRun_e623 {
  strings:
    $key_e623 = { b5 4c [2] 91 42 [2] ba 6e [2] 94 4c [2] 80 57 [2] 8f 4d [2] 91 50 [2] 93 51 [2] 88 57 [2] 94 50 [2] 88 7f }

  condition:
    any of them
}