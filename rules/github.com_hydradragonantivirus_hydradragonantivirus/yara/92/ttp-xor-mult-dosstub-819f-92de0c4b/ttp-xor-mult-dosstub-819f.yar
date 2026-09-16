rule TTP_XOR_MULT_DOSStub_819f {
  strings:
    $key_819f = { d5 f7 [2] a1 ef [2] e6 ed [2] a1 fc [2] ef f0 [2] e3 fa [2] f4 f1 [2] ef bf [2] d2 }

  condition:
    any of them
}