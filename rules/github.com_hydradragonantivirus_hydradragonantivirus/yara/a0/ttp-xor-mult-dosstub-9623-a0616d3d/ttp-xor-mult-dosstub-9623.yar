rule TTP_XOR_MULT_DOSStub_9623 {
  strings:
    $key_9623 = { c2 4b [2] b6 53 [2] f1 51 [2] b6 40 [2] f8 4c [2] f4 46 [2] e3 4d [2] f8 03 [2] c5 }

  condition:
    any of them
}