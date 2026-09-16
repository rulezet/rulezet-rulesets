rule TTP_XOR_MULT_DOSStub_0a73 {
  strings:
    $key_0a73 = { 5e 1b [2] 2a 03 [2] 6d 01 [2] 2a 10 [2] 64 1c [2] 68 16 [2] 7f 1d [2] 64 53 [2] 59 }

  condition:
    any of them
}