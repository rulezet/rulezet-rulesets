rule TTP_XOR_MULT_DOSStub_6cfe {
  strings:
    $key_6cfe = { 38 96 [2] 4c 8e [2] 0b 8c [2] 4c 9d [2] 02 91 [2] 0e 9b [2] 19 90 [2] 02 de [2] 3f }

  condition:
    any of them
}