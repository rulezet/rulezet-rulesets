rule TTP_XOR_MULT_DOSStub_5caf {
  strings:
    $key_5caf = { 08 c7 [2] 7c df [2] 3b dd [2] 7c cc [2] 32 c0 [2] 3e ca [2] 29 c1 [2] 32 8f [2] 0f }

  condition:
    any of them
}