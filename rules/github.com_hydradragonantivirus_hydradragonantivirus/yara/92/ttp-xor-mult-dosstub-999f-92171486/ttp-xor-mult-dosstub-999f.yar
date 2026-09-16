rule TTP_XOR_MULT_DOSStub_999f {
  strings:
    $key_999f = { cd f7 [2] b9 ef [2] fe ed [2] b9 fc [2] f7 f0 [2] fb fa [2] ec f1 [2] f7 bf [2] ca }

  condition:
    any of them
}