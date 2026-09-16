rule TTP_XOR_MULT_DOSStub_dcaf {
  strings:
    $key_dcaf = { 88 c7 [2] fc df [2] bb dd [2] fc cc [2] b2 c0 [2] be ca [2] a9 c1 [2] b2 8f [2] 8f }

  condition:
    any of them
}