rule TTP_XOR_MULT_DOSStub_9167 {
  strings:
    $key_9167 = { c5 0f [2] b1 17 [2] f6 15 [2] b1 04 [2] ff 08 [2] f3 02 [2] e4 09 [2] ff 47 [2] c2 }

  condition:
    any of them
}