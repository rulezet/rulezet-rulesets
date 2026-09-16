rule TTP_XOR_MULT_DOSStub_dcff {
  strings:
    $key_dcff = { 88 97 [2] fc 8f [2] bb 8d [2] fc 9c [2] b2 90 [2] be 9a [2] a9 91 [2] b2 df [2] 8f }

  condition:
    any of them
}