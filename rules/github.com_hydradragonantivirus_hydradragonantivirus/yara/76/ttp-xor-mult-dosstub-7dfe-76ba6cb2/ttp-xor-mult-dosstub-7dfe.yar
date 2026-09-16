rule TTP_XOR_MULT_DOSStub_7dfe {
  strings:
    $key_7dfe = { 29 96 [2] 5d 8e [2] 1a 8c [2] 5d 9d [2] 13 91 [2] 1f 9b [2] 08 90 [2] 13 de [2] 2e }

  condition:
    any of them
}