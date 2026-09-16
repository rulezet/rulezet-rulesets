rule TTP_XOR_MULT_DOSStub_05df {
  strings:
    $key_05df = { 51 b7 [2] 25 af [2] 62 ad [2] 25 bc [2] 6b b0 [2] 67 ba [2] 70 b1 [2] 6b ff [2] 56 }

  condition:
    any of them
}