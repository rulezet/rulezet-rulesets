rule TTP_XOR_MULT_DOSStub_1eaf {
  strings:
    $key_1eaf = { 4a c7 [2] 3e df [2] 79 dd [2] 3e cc [2] 70 c0 [2] 7c ca [2] 6b c1 [2] 70 8f [2] 4d }

  condition:
    any of them
}