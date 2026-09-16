rule TTP_XOR_MULT_DOSStub_b9bd {
  strings:
    $key_b9bd = { ed d5 [2] 99 cd [2] de cf [2] 99 de [2] d7 d2 [2] db d8 [2] cc d3 [2] d7 9d [2] ea }

  condition:
    any of them
}