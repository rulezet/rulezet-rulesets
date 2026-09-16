rule TTP_XOR_MULT_DOSStub_0eaf {
  strings:
    $key_0eaf = { 5a c7 [2] 2e df [2] 69 dd [2] 2e cc [2] 60 c0 [2] 6c ca [2] 7b c1 [2] 60 8f [2] 5d }

  condition:
    any of them
}