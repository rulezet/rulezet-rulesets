rule TTP_XOR_MULT_DOSStub_99df {
  strings:
    $key_99df = { cd b7 [2] b9 af [2] fe ad [2] b9 bc [2] f7 b0 [2] fb ba [2] ec b1 [2] f7 ff [2] ca }

  condition:
    any of them
}