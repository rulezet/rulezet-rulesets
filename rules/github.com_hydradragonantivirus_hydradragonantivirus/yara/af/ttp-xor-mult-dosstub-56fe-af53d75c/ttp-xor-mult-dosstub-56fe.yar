rule TTP_XOR_MULT_DOSStub_56fe {
  strings:
    $key_56fe = { 02 96 [2] 76 8e [2] 31 8c [2] 76 9d [2] 38 91 [2] 34 9b [2] 23 90 [2] 38 de [2] 05 }

  condition:
    any of them
}