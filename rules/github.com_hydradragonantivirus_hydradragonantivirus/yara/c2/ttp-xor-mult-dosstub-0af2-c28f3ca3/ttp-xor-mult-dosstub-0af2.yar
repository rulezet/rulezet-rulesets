rule TTP_XOR_MULT_DOSStub_0af2 {
  strings:
    $key_0af2 = { 5e 9a [2] 2a 82 [2] 6d 80 [2] 2a 91 [2] 64 9d [2] 68 97 [2] 7f 9c [2] 64 d2 [2] 59 }

  condition:
    any of them
}