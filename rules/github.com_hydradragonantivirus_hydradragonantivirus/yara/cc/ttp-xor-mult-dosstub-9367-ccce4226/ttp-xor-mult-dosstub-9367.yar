rule TTP_XOR_MULT_DOSStub_9367 {
  strings:
    $key_9367 = { c7 0f [2] b3 17 [2] f4 15 [2] b3 04 [2] fd 08 [2] f1 02 [2] e6 09 [2] fd 47 [2] c0 }

  condition:
    any of them
}