rule TTP_XOR_MULT_DOSStub_936f {
  strings:
    $key_936f = { c7 07 [2] b3 1f [2] f4 1d [2] b3 0c [2] fd 00 [2] f1 0a [2] e6 01 [2] fd 4f [2] c0 }

  condition:
    any of them
}