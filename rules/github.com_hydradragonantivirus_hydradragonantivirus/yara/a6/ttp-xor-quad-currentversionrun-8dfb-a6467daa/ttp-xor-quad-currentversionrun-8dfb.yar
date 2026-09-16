rule TTP_XOR_QUAD_CurrentVersionRun_8dfb {
  strings:
    $key_8dfb = { de 94 [2] fa 9a [2] d1 b6 [2] ff 94 [2] eb 8f [2] e4 95 [2] fa 88 [2] f8 89 [2] e3 8f [2] ff 88 [2] e3 a7 }

  condition:
    any of them
}