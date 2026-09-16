rule TTP_XOR_MULT_DOSStub_37fe {
  strings:
    $key_37fe = { 63 96 [2] 17 8e [2] 50 8c [2] 17 9d [2] 59 91 [2] 55 9b [2] 42 90 [2] 59 de [2] 64 }

  condition:
    any of them
}