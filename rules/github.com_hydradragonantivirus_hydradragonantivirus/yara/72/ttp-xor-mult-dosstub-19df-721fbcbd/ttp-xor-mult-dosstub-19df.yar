rule TTP_XOR_MULT_DOSStub_19df {
  strings:
    $key_19df = { 4d b7 [2] 39 af [2] 7e ad [2] 39 bc [2] 77 b0 [2] 7b ba [2] 6c b1 [2] 77 ff [2] 4a }

  condition:
    any of them
}