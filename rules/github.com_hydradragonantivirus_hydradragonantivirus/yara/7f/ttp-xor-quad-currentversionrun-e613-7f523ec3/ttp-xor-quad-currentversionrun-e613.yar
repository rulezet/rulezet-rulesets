rule TTP_XOR_QUAD_CurrentVersionRun_e613 {
  strings:
    $key_e613 = { b5 7c [2] 91 72 [2] ba 5e [2] 94 7c [2] 80 67 [2] 8f 7d [2] 91 60 [2] 93 61 [2] 88 67 [2] 94 60 [2] 88 4f }

  condition:
    any of them
}