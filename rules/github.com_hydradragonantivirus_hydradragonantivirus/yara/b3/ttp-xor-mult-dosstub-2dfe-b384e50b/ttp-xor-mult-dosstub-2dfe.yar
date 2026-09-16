rule TTP_XOR_MULT_DOSStub_2dfe {
  strings:
    $key_2dfe = { 79 96 [2] 0d 8e [2] 4a 8c [2] 0d 9d [2] 43 91 [2] 4f 9b [2] 58 90 [2] 43 de [2] 7e }

  condition:
    any of them
}