rule TTP_XOR_QUAD_CurrentVersionRun_8d0a {
  strings:
    $key_8d0a = { de 65 [2] fa 6b [2] d1 47 [2] ff 65 [2] eb 7e [2] e4 64 [2] fa 79 [2] f8 78 [2] e3 7e [2] ff 79 [2] e3 56 }

  condition:
    any of them
}