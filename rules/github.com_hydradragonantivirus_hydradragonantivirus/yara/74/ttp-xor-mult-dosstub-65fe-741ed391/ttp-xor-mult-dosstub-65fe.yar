rule TTP_XOR_MULT_DOSStub_65fe {
  strings:
    $key_65fe = { 31 96 [2] 45 8e [2] 02 8c [2] 45 9d [2] 0b 91 [2] 07 9b [2] 10 90 [2] 0b de [2] 36 }

  condition:
    any of them
}