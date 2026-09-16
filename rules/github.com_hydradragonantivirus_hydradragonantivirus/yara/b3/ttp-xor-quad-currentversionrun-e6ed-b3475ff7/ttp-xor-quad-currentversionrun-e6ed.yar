rule TTP_XOR_QUAD_CurrentVersionRun_e6ed {
  strings:
    $key_e6ed = { b5 82 [2] 91 8c [2] ba a0 [2] 94 82 [2] 80 99 [2] 8f 83 [2] 91 9e [2] 93 9f [2] 88 99 [2] 94 9e [2] 88 b1 }

  condition:
    any of them
}