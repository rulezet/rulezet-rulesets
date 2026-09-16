rule TTP_XOR_MULT_DOSStub_930f {
  strings:
    $key_930f = { c7 67 [2] b3 7f [2] f4 7d [2] b3 6c [2] fd 60 [2] f1 6a [2] e6 61 [2] fd 2f [2] c0 }

  condition:
    any of them
}