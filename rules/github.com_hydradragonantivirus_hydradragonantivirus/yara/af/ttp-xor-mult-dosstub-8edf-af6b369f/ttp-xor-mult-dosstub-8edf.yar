rule TTP_XOR_MULT_DOSStub_8edf {
  strings:
    $key_8edf = { da b7 [2] ae af [2] e9 ad [2] ae bc [2] e0 b0 [2] ec ba [2] fb b1 [2] e0 ff [2] dd }

  condition:
    any of them
}