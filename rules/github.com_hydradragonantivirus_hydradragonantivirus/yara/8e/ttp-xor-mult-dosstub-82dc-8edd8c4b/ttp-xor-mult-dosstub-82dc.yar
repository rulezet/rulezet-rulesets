rule TTP_XOR_MULT_DOSStub_82dc {
  strings:
    $key_82dc = { d6 b4 [2] a2 ac [2] e5 ae [2] a2 bf [2] ec b3 [2] e0 b9 [2] f7 b2 [2] ec fc [2] d1 }

  condition:
    any of them
}