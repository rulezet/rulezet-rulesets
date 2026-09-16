rule TTP_XOR_MULT_DOSStub_3caf {
  strings:
    $key_3caf = { 68 c7 [2] 1c df [2] 5b dd [2] 1c cc [2] 52 c0 [2] 5e ca [2] 49 c1 [2] 52 8f [2] 6f }

  condition:
    any of them
}