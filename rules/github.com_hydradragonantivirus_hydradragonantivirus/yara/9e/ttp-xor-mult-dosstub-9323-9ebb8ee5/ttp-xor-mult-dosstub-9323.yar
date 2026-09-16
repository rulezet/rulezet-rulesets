rule TTP_XOR_MULT_DOSStub_9323 {
  strings:
    $key_9323 = { c7 4b [2] b3 53 [2] f4 51 [2] b3 40 [2] fd 4c [2] f1 46 [2] e6 4d [2] fd 03 [2] c0 }

  condition:
    any of them
}