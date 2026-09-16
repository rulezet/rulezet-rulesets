rule TTP_XOR_MULT_DOSStub_fadc {
  strings:
    $key_fadc = { ae b4 [2] da ac [2] 9d ae [2] da bf [2] 94 b3 [2] 98 b9 [2] 8f b2 [2] 94 fc [2] a9 }

  condition:
    any of them
}