rule TTP_XOR_MULT_DOSStub_0292 {
  strings:
    $key_0292 = { 56 fa [2] 22 e2 [2] 65 e0 [2] 22 f1 [2] 6c fd [2] 60 f7 [2] 77 fc [2] 6c b2 [2] 51 }

  condition:
    any of them
}