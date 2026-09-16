rule TTP_XOR_QUAD_CurrentVersionRun_8dda {
  strings:
    $key_8dda = { de b5 [2] fa bb [2] d1 97 [2] ff b5 [2] eb ae [2] e4 b4 [2] fa a9 [2] f8 a8 [2] e3 ae [2] ff a9 [2] e3 86 }

  condition:
    any of them
}