rule TTP_XOR_QUAD_CurrentVersionRun_8d7e {
  strings:
    $key_8d7e = { de 11 [2] fa 1f [2] d1 33 [2] ff 11 [2] eb 0a [2] e4 10 [2] fa 0d [2] f8 0c [2] e3 0a [2] ff 0d [2] e3 22 }

  condition:
    any of them
}