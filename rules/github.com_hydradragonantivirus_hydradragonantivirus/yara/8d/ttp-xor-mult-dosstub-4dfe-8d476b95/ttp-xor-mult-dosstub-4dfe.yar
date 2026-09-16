rule TTP_XOR_MULT_DOSStub_4dfe {
  strings:
    $key_4dfe = { 19 96 [2] 6d 8e [2] 2a 8c [2] 6d 9d [2] 23 91 [2] 2f 9b [2] 38 90 [2] 23 de [2] 1e }

  condition:
    any of them
}