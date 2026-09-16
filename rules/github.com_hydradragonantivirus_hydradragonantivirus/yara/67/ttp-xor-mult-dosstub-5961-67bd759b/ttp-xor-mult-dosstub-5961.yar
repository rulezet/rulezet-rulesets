rule TTP_XOR_MULT_DOSStub_5961 {
  strings:
    $key_5961 = { 0d 09 [2] 79 11 [2] 3e 13 [2] 79 02 [2] 37 0e [2] 3b 04 [2] 2c 0f [2] 37 41 [2] 0a }

  condition:
    any of them
}