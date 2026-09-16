rule TTP_XOR_QUAD_CurrentVersionRun_8d14 {
  strings:
    $key_8d14 = { de 7b [2] fa 75 [2] d1 59 [2] ff 7b [2] eb 60 [2] e4 7a [2] fa 67 [2] f8 66 [2] e3 60 [2] ff 67 [2] e3 48 }

  condition:
    any of them
}