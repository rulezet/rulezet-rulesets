rule TTP_XOR_MULT_DOSStub_9373 {
  strings:
    $key_9373 = { c7 1b [2] b3 03 [2] f4 01 [2] b3 10 [2] fd 1c [2] f1 16 [2] e6 1d [2] fd 53 [2] c0 }

  condition:
    any of them
}