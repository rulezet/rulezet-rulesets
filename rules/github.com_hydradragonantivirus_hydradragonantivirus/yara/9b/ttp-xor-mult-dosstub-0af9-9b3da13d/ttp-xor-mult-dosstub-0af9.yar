rule TTP_XOR_MULT_DOSStub_0af9 {
  strings:
    $key_0af9 = { 5e 91 [2] 2a 89 [2] 6d 8b [2] 2a 9a [2] 64 96 [2] 68 9c [2] 7f 97 [2] 64 d9 [2] 59 }

  condition:
    any of them
}