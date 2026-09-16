rule TTP_XOR_MULT_DOSStub_16fe {
  strings:
    $key_16fe = { 42 96 [2] 36 8e [2] 71 8c [2] 36 9d [2] 78 91 [2] 74 9b [2] 63 90 [2] 78 de [2] 45 }

  condition:
    any of them
}