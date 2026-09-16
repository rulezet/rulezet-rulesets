rule TTP_XOR_QUAD_CurrentVersionRun_8dff {
  strings:
    $key_8dff = { de 90 [2] fa 9e [2] d1 b2 [2] ff 90 [2] eb 8b [2] e4 91 [2] fa 8c [2] f8 8d [2] e3 8b [2] ff 8c [2] e3 a3 }

  condition:
    any of them
}