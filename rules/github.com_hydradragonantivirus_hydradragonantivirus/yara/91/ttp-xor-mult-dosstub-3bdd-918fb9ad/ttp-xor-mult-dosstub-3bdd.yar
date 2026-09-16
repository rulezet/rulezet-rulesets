rule TTP_XOR_MULT_DOSStub_3bdd {
  strings:
    $key_3bdd = { 6f b5 [2] 1b ad [2] 5c af [2] 1b be [2] 55 b2 [2] 59 b8 [2] 4e b3 [2] 55 fd [2] 68 }

  condition:
    any of them
}