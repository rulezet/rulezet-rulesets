rule TTP_XOR_MULT_DOSStub_f8da {
  strings:
    $key_f8da = { ac b2 [2] d8 aa [2] 9f a8 [2] d8 b9 [2] 96 b5 [2] 9a bf [2] 8d b4 [2] 96 fa [2] ab }

  condition:
    any of them
}