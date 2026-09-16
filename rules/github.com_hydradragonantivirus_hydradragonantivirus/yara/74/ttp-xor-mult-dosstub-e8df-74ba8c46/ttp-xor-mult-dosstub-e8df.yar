rule TTP_XOR_MULT_DOSStub_e8df {
  strings:
    $key_e8df = { bc b7 [2] c8 af [2] 8f ad [2] c8 bc [2] 86 b0 [2] 8a ba [2] 9d b1 [2] 86 ff [2] bb }

  condition:
    any of them
}