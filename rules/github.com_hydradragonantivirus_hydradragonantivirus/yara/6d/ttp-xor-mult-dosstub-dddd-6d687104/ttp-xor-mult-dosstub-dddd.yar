rule TTP_XOR_MULT_DOSStub_dddd {
  strings:
    $key_dddd = { 89 b5 [2] fd ad [2] ba af [2] fd be [2] b3 b2 [2] bf b8 [2] a8 b3 [2] b3 fd [2] 8e }

  condition:
    any of them
}