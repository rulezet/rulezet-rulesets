rule TTP_XOR_MULT_DOSStub_1caf {
  strings:
    $key_1caf = { 48 c7 [2] 3c df [2] 7b dd [2] 3c cc [2] 72 c0 [2] 7e ca [2] 69 c1 [2] 72 8f [2] 4f }

  condition:
    any of them
}