rule TTP_XOR_MULT_DOSStub_9371 {
  strings:
    $key_9371 = { c7 19 [2] b3 01 [2] f4 03 [2] b3 12 [2] fd 1e [2] f1 14 [2] e6 1f [2] fd 51 [2] c0 }

  condition:
    any of them
}