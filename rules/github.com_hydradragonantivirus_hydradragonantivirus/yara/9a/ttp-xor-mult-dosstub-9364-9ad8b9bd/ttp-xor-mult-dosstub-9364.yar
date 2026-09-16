rule TTP_XOR_MULT_DOSStub_9364 {
  strings:
    $key_9364 = { c7 0c [2] b3 14 [2] f4 16 [2] b3 07 [2] fd 0b [2] f1 01 [2] e6 0a [2] fd 44 [2] c0 }

  condition:
    any of them
}