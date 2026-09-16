rule TTP_XOR_MULT_DOSStub_068d {
  strings:
    $key_068d = { 52 e5 [2] 26 fd [2] 61 ff [2] 26 ee [2] 68 e2 [2] 64 e8 [2] 73 e3 [2] 68 ad [2] 55 }

  condition:
    any of them
}