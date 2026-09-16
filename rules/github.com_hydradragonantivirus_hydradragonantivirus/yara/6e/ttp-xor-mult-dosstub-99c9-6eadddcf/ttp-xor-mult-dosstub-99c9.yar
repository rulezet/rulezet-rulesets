rule TTP_XOR_MULT_DOSStub_99c9 {
  strings:
    $key_99c9 = { cd a1 [2] b9 b9 [2] fe bb [2] b9 aa [2] f7 a6 [2] fb ac [2] ec a7 [2] f7 e9 [2] ca }

  condition:
    any of them
}