rule TTP_XOR_MULT_DOSStub_9983 {
  strings:
    $key_9983 = { cd eb [2] b9 f3 [2] fe f1 [2] b9 e0 [2] f7 ec [2] fb e6 [2] ec ed [2] f7 a3 [2] ca }

  condition:
    any of them
}