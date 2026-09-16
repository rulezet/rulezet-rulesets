rule TTP_XOR_MULT_DOSStub_0a50 {
  strings:
    $key_0a50 = { 5e 38 [2] 2a 20 [2] 6d 22 [2] 2a 33 [2] 64 3f [2] 68 35 [2] 7f 3e [2] 64 70 [2] 59 }

  condition:
    any of them
}