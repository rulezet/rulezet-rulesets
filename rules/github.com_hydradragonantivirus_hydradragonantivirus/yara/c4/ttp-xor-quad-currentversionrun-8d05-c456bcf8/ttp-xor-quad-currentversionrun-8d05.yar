rule TTP_XOR_QUAD_CurrentVersionRun_8d05 {
  strings:
    $key_8d05 = { de 6a [2] fa 64 [2] d1 48 [2] ff 6a [2] eb 71 [2] e4 6b [2] fa 76 [2] f8 77 [2] e3 71 [2] ff 76 [2] e3 59 }

  condition:
    any of them
}