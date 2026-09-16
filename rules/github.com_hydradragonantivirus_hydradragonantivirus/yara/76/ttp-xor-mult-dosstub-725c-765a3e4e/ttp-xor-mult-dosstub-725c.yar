rule TTP_XOR_MULT_DOSStub_725c {
  strings:
    $key_725c = { 26 34 [2] 52 2c [2] 15 2e [2] 52 3f [2] 1c 33 [2] 10 39 [2] 07 32 [2] 1c 7c [2] 21 }

  condition:
    any of them
}