rule TTP_XOR_MULT_DOSStub_9335 {
  strings:
    $key_9335 = { c7 5d [2] b3 45 [2] f4 47 [2] b3 56 [2] fd 5a [2] f1 50 [2] e6 5b [2] fd 15 [2] c0 }

  condition:
    any of them
}