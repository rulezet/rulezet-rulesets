rule TTP_XOR_MULT_DOSStub_9bdc {
  strings:
    $key_9bdc = { cf b4 [2] bb ac [2] fc ae [2] bb bf [2] f5 b3 [2] f9 b9 [2] ee b2 [2] f5 fc [2] c8 }

  condition:
    any of them
}