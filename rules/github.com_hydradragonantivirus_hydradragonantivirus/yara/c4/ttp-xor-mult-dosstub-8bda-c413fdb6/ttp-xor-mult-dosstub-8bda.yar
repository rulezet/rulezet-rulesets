rule TTP_XOR_MULT_DOSStub_8bda {
  strings:
    $key_8bda = { df b2 [2] ab aa [2] ec a8 [2] ab b9 [2] e5 b5 [2] e9 bf [2] fe b4 [2] e5 fa [2] d8 }

  condition:
    any of them
}