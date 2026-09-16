rule TTP_XOR_MULT_DOSStub_6caf {
  strings:
    $key_6caf = { 38 c7 [2] 4c df [2] 0b dd [2] 4c cc [2] 02 c0 [2] 0e ca [2] 19 c1 [2] 02 8f [2] 3f }

  condition:
    any of them
}