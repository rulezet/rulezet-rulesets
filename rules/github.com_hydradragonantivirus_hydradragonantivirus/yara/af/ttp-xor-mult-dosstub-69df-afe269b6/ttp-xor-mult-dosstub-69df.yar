rule TTP_XOR_MULT_DOSStub_69df {
  strings:
    $key_69df = { 3d b7 [2] 49 af [2] 0e ad [2] 49 bc [2] 07 b0 [2] 0b ba [2] 1c b1 [2] 07 ff [2] 3a }

  condition:
    any of them
}