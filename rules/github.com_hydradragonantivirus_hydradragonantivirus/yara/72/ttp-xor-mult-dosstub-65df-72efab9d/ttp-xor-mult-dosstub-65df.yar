rule TTP_XOR_MULT_DOSStub_65df {
  strings:
    $key_65df = { 31 b7 [2] 45 af [2] 02 ad [2] 45 bc [2] 0b b0 [2] 07 ba [2] 10 b1 [2] 0b ff [2] 36 }

  condition:
    any of them
}