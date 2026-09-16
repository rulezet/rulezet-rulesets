rule TTP_XOR_MULT_DOSStub_9bb8 {
  strings:
    $key_9bb8 = { cf d0 [2] bb c8 [2] fc ca [2] bb db [2] f5 d7 [2] f9 dd [2] ee d6 [2] f5 98 [2] c8 }

  condition:
    any of them
}