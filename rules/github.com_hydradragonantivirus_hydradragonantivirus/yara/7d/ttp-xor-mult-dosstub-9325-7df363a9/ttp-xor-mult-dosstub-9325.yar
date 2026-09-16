rule TTP_XOR_MULT_DOSStub_9325 {
  strings:
    $key_9325 = { c7 4d [2] b3 55 [2] f4 57 [2] b3 46 [2] fd 4a [2] f1 40 [2] e6 4b [2] fd 05 [2] c0 }

  condition:
    any of them
}