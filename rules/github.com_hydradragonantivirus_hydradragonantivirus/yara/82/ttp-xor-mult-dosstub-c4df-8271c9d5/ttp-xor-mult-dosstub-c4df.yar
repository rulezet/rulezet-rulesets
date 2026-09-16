rule TTP_XOR_MULT_DOSStub_c4df {
  strings:
    $key_c4df = { 90 b7 [2] e4 af [2] a3 ad [2] e4 bc [2] aa b0 [2] a6 ba [2] b1 b1 [2] aa ff [2] 97 }

  condition:
    any of them
}