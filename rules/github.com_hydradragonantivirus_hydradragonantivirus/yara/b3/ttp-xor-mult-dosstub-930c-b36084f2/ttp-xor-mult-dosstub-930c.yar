rule TTP_XOR_MULT_DOSStub_930c {
  strings:
    $key_930c = { c7 64 [2] b3 7c [2] f4 7e [2] b3 6f [2] fd 63 [2] f1 69 [2] e6 62 [2] fd 2c [2] c0 }

  condition:
    any of them
}