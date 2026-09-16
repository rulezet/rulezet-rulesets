rule TTP_XOR_QUAD_CurrentVersionRun_8cda {
  strings:
    $key_8cda = { df b5 [2] fb bb [2] d0 97 [2] fe b5 [2] ea ae [2] e5 b4 [2] fb a9 [2] f9 a8 [2] e2 ae [2] fe a9 [2] e2 86 }

  condition:
    any of them
}