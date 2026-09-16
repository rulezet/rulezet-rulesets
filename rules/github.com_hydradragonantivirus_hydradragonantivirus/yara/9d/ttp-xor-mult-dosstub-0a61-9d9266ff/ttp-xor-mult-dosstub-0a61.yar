rule TTP_XOR_MULT_DOSStub_0a61 {
  strings:
    $key_0a61 = { 5e 09 [2] 2a 11 [2] 6d 13 [2] 2a 02 [2] 64 0e [2] 68 04 [2] 7f 0f [2] 64 41 [2] 59 }

  condition:
    any of them
}