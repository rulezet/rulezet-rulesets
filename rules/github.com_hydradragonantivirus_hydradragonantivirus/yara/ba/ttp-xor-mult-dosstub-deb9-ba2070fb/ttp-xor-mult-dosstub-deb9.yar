rule TTP_XOR_MULT_DOSStub_deb9 {
  strings:
    $key_deb9 = { 8a d1 [2] fe c9 [2] b9 cb [2] fe da [2] b0 d6 [2] bc dc [2] ab d7 [2] b0 99 [2] 8d }

  condition:
    any of them
}