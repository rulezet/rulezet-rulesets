rule TTP_XOR_MULT_DOSStub_91bf {
  strings:
    $key_91bf = { c5 d7 [2] b1 cf [2] f6 cd [2] b1 dc [2] ff d0 [2] f3 da [2] e4 d1 [2] ff 9f [2] c2 }

  condition:
    any of them
}