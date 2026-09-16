rule TTP_XOR_MULT_DOSStub_90dc {
  strings:
    $key_90dc = { c4 b4 [2] b0 ac [2] f7 ae [2] b0 bf [2] fe b3 [2] f2 b9 [2] e5 b2 [2] fe fc [2] c3 }

  condition:
    any of them
}