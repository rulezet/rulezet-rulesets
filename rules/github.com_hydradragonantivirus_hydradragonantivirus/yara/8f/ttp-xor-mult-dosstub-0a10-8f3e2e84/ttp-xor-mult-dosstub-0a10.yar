rule TTP_XOR_MULT_DOSStub_0a10 {
  strings:
    $key_0a10 = { 5e 78 [2] 2a 60 [2] 6d 62 [2] 2a 73 [2] 64 7f [2] 68 75 [2] 7f 7e [2] 64 30 [2] 59 }

  condition:
    any of them
}