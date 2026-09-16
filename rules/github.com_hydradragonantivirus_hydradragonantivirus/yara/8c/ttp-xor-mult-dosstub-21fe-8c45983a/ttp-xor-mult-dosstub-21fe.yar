rule TTP_XOR_MULT_DOSStub_21fe {
  strings:
    $key_21fe = { 75 96 [2] 01 8e [2] 46 8c [2] 01 9d [2] 4f 91 [2] 43 9b [2] 54 90 [2] 4f de [2] 72 }

  condition:
    any of them
}