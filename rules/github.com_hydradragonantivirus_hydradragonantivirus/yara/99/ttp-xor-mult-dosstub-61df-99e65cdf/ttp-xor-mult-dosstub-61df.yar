rule TTP_XOR_MULT_DOSStub_61df {
  strings:
    $key_61df = { 35 b7 [2] 41 af [2] 06 ad [2] 41 bc [2] 0f b0 [2] 03 ba [2] 14 b1 [2] 0f ff [2] 32 }

  condition:
    any of them
}