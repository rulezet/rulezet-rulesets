rule TTP_XOR_QUAD_CurrentVersionRun_e6fd {
  strings:
    $key_e6fd = { b5 92 [2] 91 9c [2] ba b0 [2] 94 92 [2] 80 89 [2] 8f 93 [2] 91 8e [2] 93 8f [2] 88 89 [2] 94 8e [2] 88 a1 }

  condition:
    any of them
}