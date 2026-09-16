rule TTP_XOR_MULT_DOSStub_a043 {
  strings:
    $key_a043 = { f4 2b [2] 80 33 [2] c7 31 [2] 80 20 [2] ce 2c [2] c2 26 [2] d5 2d [2] ce 63 [2] f3 }

  condition:
    any of them
}