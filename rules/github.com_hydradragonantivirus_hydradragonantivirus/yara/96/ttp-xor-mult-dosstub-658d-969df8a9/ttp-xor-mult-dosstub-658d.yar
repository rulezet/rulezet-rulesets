rule TTP_XOR_MULT_DOSStub_658d {
  strings:
    $key_658d = { 31 e5 [2] 45 fd [2] 02 ff [2] 45 ee [2] 0b e2 [2] 07 e8 [2] 10 e3 [2] 0b ad [2] 36 }

  condition:
    any of them
}