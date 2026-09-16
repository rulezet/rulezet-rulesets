rule TTP_XOR_MULT_DOSStub_c36e {
  strings:
    $key_c36e = { 97 06 [2] e3 1e [2] a4 1c [2] e3 0d [2] ad 01 [2] a1 0b [2] b6 00 [2] ad 4e [2] 90 }

  condition:
    any of them
}