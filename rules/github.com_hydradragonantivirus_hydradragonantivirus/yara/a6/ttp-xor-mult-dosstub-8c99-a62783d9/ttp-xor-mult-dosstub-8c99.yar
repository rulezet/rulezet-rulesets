rule TTP_XOR_MULT_DOSStub_8c99 {
  strings:
    $key_8c99 = { d8 f1 [2] ac e9 [2] eb eb [2] ac fa [2] e2 f6 [2] ee fc [2] f9 f7 [2] e2 b9 [2] df }

  condition:
    any of them
}