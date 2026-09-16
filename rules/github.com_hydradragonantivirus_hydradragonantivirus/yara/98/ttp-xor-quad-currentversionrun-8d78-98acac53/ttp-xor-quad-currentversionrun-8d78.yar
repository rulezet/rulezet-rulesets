rule TTP_XOR_QUAD_CurrentVersionRun_8d78 {
  strings:
    $key_8d78 = { de 17 [2] fa 19 [2] d1 35 [2] ff 17 [2] eb 0c [2] e4 16 [2] fa 0b [2] f8 0a [2] e3 0c [2] ff 0b [2] e3 24 }

  condition:
    any of them
}