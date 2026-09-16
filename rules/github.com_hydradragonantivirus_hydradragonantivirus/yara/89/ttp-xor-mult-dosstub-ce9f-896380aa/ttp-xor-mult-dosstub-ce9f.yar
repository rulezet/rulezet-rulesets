rule TTP_XOR_MULT_DOSStub_ce9f {
  strings:
    $key_ce9f = { 9a f7 [2] ee ef [2] a9 ed [2] ee fc [2] a0 f0 [2] ac fa [2] bb f1 [2] a0 bf [2] 9d }

  condition:
    any of them
}