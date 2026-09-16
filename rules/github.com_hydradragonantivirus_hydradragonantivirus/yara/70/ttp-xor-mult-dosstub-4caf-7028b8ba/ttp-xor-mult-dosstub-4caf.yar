rule TTP_XOR_MULT_DOSStub_4caf {
  strings:
    $key_4caf = { 18 c7 [2] 6c df [2] 2b dd [2] 6c cc [2] 22 c0 [2] 2e ca [2] 39 c1 [2] 22 8f [2] 1f }

  condition:
    any of them
}