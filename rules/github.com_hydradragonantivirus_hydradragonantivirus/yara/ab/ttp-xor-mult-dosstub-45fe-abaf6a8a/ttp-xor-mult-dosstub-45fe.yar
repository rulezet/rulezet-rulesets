rule TTP_XOR_MULT_DOSStub_45fe {
  strings:
    $key_45fe = { 11 96 [2] 65 8e [2] 22 8c [2] 65 9d [2] 2b 91 [2] 27 9b [2] 30 90 [2] 2b de [2] 16 }

  condition:
    any of them
}