rule TTP_XOR_QUAD_CurrentVersionRun_e6ff {
  strings:
    $key_e6ff = { b5 90 [2] 91 9e [2] ba b2 [2] 94 90 [2] 80 8b [2] 8f 91 [2] 91 8c [2] 93 8d [2] 88 8b [2] 94 8c [2] 88 a3 }

  condition:
    any of them
}