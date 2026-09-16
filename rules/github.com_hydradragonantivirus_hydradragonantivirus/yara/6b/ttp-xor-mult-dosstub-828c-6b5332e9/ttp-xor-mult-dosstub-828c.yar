rule TTP_XOR_MULT_DOSStub_828c {
  strings:
    $key_828c = { d6 e4 [2] a2 fc [2] e5 fe [2] a2 ef [2] ec e3 [2] e0 e9 [2] f7 e2 [2] ec ac [2] d1 }

  condition:
    any of them
}