rule TTP_XOR_QUAD_CurrentVersionRun_8de8 {
  strings:
    $key_8de8 = { de 87 [2] fa 89 [2] d1 a5 [2] ff 87 [2] eb 9c [2] e4 86 [2] fa 9b [2] f8 9a [2] e3 9c [2] ff 9b [2] e3 b4 }

  condition:
    any of them
}