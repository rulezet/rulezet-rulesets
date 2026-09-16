rule TTP_XOR_MULT_DOSStub_0ae3 {
  strings:
    $key_0ae3 = { 5e 8b [2] 2a 93 [2] 6d 91 [2] 2a 80 [2] 64 8c [2] 68 86 [2] 7f 8d [2] 64 c3 [2] 59 }

  condition:
    any of them
}