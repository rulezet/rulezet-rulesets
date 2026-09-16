rule TTP_XOR_QUAD_CurrentVersionRun_8df5 {
  strings:
    $key_8df5 = { de 9a [2] fa 94 [2] d1 b8 [2] ff 9a [2] eb 81 [2] e4 9b [2] fa 86 [2] f8 87 [2] e3 81 [2] ff 86 [2] e3 a9 }

  condition:
    any of them
}