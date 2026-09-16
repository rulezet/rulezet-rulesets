rule TTP_XOR_MULT_DOSStub_140c {
  strings:
    $key_140c = { 40 64 [2] 34 7c [2] 73 7e [2] 34 6f [2] 7a 63 [2] 76 69 [2] 61 62 [2] 7a 2c [2] 47 }

  condition:
    any of them
}