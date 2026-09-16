rule TTP_XOR_MULT_DOSStub_2bdd {
  strings:
    $key_2bdd = { 7f b5 [2] 0b ad [2] 4c af [2] 0b be [2] 45 b2 [2] 49 b8 [2] 5e b3 [2] 45 fd [2] 78 }

  condition:
    any of them
}