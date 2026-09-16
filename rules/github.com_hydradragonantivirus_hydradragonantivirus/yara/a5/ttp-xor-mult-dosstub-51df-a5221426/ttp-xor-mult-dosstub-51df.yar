rule TTP_XOR_MULT_DOSStub_51df {
  strings:
    $key_51df = { 05 b7 [2] 71 af [2] 36 ad [2] 71 bc [2] 3f b0 [2] 33 ba [2] 24 b1 [2] 3f ff [2] 02 }

  condition:
    any of them
}