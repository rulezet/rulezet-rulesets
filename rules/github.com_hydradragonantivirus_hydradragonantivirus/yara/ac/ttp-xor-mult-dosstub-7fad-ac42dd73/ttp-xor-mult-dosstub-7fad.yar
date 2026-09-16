rule TTP_XOR_MULT_DOSStub_7fad {
  strings:
    $key_7fad = { 2b c5 [2] 5f dd [2] 18 df [2] 5f ce [2] 11 c2 [2] 1d c8 [2] 0a c3 [2] 11 8d [2] 2c }

  condition:
    any of them
}