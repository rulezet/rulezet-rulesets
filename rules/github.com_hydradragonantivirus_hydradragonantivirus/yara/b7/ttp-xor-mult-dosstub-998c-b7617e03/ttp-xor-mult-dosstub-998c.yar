rule TTP_XOR_MULT_DOSStub_998c {
  strings:
    $key_998c = { cd e4 [2] b9 fc [2] fe fe [2] b9 ef [2] f7 e3 [2] fb e9 [2] ec e2 [2] f7 ac [2] ca }

  condition:
    any of them
}