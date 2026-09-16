rule TTP_XOR_MULT_DOSStub_15fe {
  strings:
    $key_15fe = { 41 96 [2] 35 8e [2] 72 8c [2] 35 9d [2] 7b 91 [2] 77 9b [2] 60 90 [2] 7b de [2] 46 }

  condition:
    any of them
}