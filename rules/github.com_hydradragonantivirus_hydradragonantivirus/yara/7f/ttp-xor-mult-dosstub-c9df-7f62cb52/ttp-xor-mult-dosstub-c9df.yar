rule TTP_XOR_MULT_DOSStub_c9df {
  strings:
    $key_c9df = { 9d b7 [2] e9 af [2] ae ad [2] e9 bc [2] a7 b0 [2] ab ba [2] bc b1 [2] a7 ff [2] 9a }

  condition:
    any of them
}