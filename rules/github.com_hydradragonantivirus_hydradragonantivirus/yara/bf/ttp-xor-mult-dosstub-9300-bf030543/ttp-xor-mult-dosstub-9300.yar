rule TTP_XOR_MULT_DOSStub_9300 {
  strings:
    $key_9300 = { c7 68 [2] b3 70 [2] f4 72 [2] b3 63 [2] fd 6f [2] f1 65 [2] e6 6e [2] fd 20 [2] c0 }

  condition:
    any of them
}