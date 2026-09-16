rule TTP_XOR_QUAD_CurrentVersionRun_8bda {
  strings:
    $key_8bda = { d8 b5 [2] fc bb [2] d7 97 [2] f9 b5 [2] ed ae [2] e2 b4 [2] fc a9 [2] fe a8 [2] e5 ae [2] f9 a9 [2] e5 86 }

  condition:
    any of them
}