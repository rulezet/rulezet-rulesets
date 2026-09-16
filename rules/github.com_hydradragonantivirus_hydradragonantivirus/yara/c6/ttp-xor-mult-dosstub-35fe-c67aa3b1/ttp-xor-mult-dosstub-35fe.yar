rule TTP_XOR_MULT_DOSStub_35fe {
  strings:
    $key_35fe = { 61 96 [2] 15 8e [2] 52 8c [2] 15 9d [2] 5b 91 [2] 57 9b [2] 40 90 [2] 5b de [2] 66 }

  condition:
    any of them
}