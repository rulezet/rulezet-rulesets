rule TTP_XOR_MULT_DOSStub_dcfe {
  strings:
    $key_dcfe = { 88 96 [2] fc 8e [2] bb 8c [2] fc 9d [2] b2 91 [2] be 9b [2] a9 90 [2] b2 de [2] 8f }

  condition:
    any of them
}