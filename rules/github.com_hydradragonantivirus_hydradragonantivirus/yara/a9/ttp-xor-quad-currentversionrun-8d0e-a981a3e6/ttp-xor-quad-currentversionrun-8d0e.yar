rule TTP_XOR_QUAD_CurrentVersionRun_8d0e {
  strings:
    $key_8d0e = { de 61 [2] fa 6f [2] d1 43 [2] ff 61 [2] eb 7a [2] e4 60 [2] fa 7d [2] f8 7c [2] e3 7a [2] ff 7d [2] e3 52 }

  condition:
    any of them
}