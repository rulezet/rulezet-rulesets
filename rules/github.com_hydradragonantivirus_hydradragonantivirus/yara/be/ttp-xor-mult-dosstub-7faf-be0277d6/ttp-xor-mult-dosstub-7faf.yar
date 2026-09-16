rule TTP_XOR_MULT_DOSStub_7faf {
  strings:
    $key_7faf = { 2b c7 [2] 5f df [2] 18 dd [2] 5f cc [2] 11 c0 [2] 1d ca [2] 0a c1 [2] 11 8f [2] 2c }

  condition:
    any of them
}