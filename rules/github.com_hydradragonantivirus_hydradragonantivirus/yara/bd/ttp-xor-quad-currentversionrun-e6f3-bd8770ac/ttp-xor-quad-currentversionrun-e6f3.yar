rule TTP_XOR_QUAD_CurrentVersionRun_e6f3 {
  strings:
    $key_e6f3 = { b5 9c [2] 91 92 [2] ba be [2] 94 9c [2] 80 87 [2] 8f 9d [2] 91 80 [2] 93 81 [2] 88 87 [2] 94 80 [2] 88 af }

  condition:
    any of them
}