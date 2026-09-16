rule TTP_XOR_MULT_DOSStub_55fe {
  strings:
    $key_55fe = { 01 96 [2] 75 8e [2] 32 8c [2] 75 9d [2] 3b 91 [2] 37 9b [2] 20 90 [2] 3b de [2] 06 }

  condition:
    any of them
}