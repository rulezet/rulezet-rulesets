rule TTP_XOR_MULT_DOSStub_99cf {
  strings:
    $key_99cf = { cd a7 [2] b9 bf [2] fe bd [2] b9 ac [2] f7 a0 [2] fb aa [2] ec a1 [2] f7 ef [2] ca }

  condition:
    any of them
}