rule TTP_XOR_MULT_DOSStub_1bdd {
  strings:
    $key_1bdd = { 4f b5 [2] 3b ad [2] 7c af [2] 3b be [2] 75 b2 [2] 79 b8 [2] 6e b3 [2] 75 fd [2] 48 }

  condition:
    any of them
}