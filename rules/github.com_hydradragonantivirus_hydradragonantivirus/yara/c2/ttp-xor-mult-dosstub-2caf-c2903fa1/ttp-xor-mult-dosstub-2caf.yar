rule TTP_XOR_MULT_DOSStub_2caf {
  strings:
    $key_2caf = { 78 c7 [2] 0c df [2] 4b dd [2] 0c cc [2] 42 c0 [2] 4e ca [2] 59 c1 [2] 42 8f [2] 7f }

  condition:
    any of them
}