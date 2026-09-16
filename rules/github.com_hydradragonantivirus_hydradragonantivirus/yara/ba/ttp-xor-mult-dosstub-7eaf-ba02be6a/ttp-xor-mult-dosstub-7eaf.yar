rule TTP_XOR_MULT_DOSStub_7eaf {
  strings:
    $key_7eaf = { 2a c7 [2] 5e df [2] 19 dd [2] 5e cc [2] 10 c0 [2] 1c ca [2] 0b c1 [2] 10 8f [2] 2d }

  condition:
    any of them
}