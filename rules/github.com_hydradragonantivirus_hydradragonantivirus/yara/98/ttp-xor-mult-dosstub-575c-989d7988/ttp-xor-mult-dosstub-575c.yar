rule TTP_XOR_MULT_DOSStub_575c {
  strings:
    $key_575c = { 03 34 [2] 77 2c [2] 30 2e [2] 77 3f [2] 39 33 [2] 35 39 [2] 22 32 [2] 39 7c [2] 04 }

  condition:
    any of them
}