rule TTP_XOR_MULT_DOSStub_9304 {
  strings:
    $key_9304 = { c7 6c [2] b3 74 [2] f4 76 [2] b3 67 [2] fd 6b [2] f1 61 [2] e6 6a [2] fd 24 [2] c0 }

  condition:
    any of them
}