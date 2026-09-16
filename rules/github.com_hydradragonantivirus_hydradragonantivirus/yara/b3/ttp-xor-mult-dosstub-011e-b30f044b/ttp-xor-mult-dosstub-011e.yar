rule TTP_XOR_MULT_DOSStub_011e {
  strings:
    $key_011e = { 55 76 [2] 21 6e [2] 66 6c [2] 21 7d [2] 6f 71 [2] 63 7b [2] 74 70 [2] 6f 3e [2] 52 }

  condition:
    any of them
}