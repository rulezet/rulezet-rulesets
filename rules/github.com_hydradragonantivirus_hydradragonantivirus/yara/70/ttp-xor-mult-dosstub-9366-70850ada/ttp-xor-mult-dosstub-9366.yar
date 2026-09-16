rule TTP_XOR_MULT_DOSStub_9366 {
  strings:
    $key_9366 = { c7 0e [2] b3 16 [2] f4 14 [2] b3 05 [2] fd 09 [2] f1 03 [2] e6 08 [2] fd 46 [2] c0 }

  condition:
    any of them
}