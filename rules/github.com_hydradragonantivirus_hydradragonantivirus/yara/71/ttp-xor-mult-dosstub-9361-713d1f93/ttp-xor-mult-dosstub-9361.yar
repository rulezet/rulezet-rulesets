rule TTP_XOR_MULT_DOSStub_9361 {
  strings:
    $key_9361 = { c7 09 [2] b3 11 [2] f4 13 [2] b3 02 [2] fd 0e [2] f1 04 [2] e6 0f [2] fd 41 [2] c0 }

  condition:
    any of them
}