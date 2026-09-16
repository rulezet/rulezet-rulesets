rule TTP_XOR_MULT_DOSStub_a0dc {
  strings:
    $key_a0dc = { f4 b4 [2] 80 ac [2] c7 ae [2] 80 bf [2] ce b3 [2] c2 b9 [2] d5 b2 [2] ce fc [2] f3 }

  condition:
    any of them
}