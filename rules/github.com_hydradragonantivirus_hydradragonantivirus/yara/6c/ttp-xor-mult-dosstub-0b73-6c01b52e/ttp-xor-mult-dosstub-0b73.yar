rule TTP_XOR_MULT_DOSStub_0b73 {
  strings:
    $key_0b73 = { 5f 1b [2] 2b 03 [2] 6c 01 [2] 2b 10 [2] 65 1c [2] 69 16 [2] 7e 1d [2] 65 53 [2] 58 }

  condition:
    any of them
}