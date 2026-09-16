rule TTP_XOR_MULT_DOSStub_2773 {
  strings:
    $key_2773 = { 73 1b [2] 07 03 [2] 40 01 [2] 07 10 [2] 49 1c [2] 45 16 [2] 52 1d [2] 49 53 [2] 74 }

  condition:
    any of them
}