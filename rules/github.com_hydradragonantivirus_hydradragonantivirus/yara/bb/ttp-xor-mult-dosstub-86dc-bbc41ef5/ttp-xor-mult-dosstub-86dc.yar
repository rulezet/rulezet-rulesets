rule TTP_XOR_MULT_DOSStub_86dc {
  strings:
    $key_86dc = { d2 b4 [2] a6 ac [2] e1 ae [2] a6 bf [2] e8 b3 [2] e4 b9 [2] f3 b2 [2] e8 fc [2] d5 }

  condition:
    any of them
}