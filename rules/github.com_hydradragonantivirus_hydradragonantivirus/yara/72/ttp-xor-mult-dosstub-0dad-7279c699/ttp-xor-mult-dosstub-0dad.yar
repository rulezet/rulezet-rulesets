rule TTP_XOR_MULT_DOSStub_0dad {
  strings:
    $key_0dad = { 59 c5 [2] 2d dd [2] 6a df [2] 2d ce [2] 63 c2 [2] 6f c8 [2] 78 c3 [2] 63 8d [2] 5e }

  condition:
    any of them
}