rule TTP_XOR_MULT_DOSStub_7bfe {
  strings:
    $key_7bfe = { 2f 96 [2] 5b 8e [2] 1c 8c [2] 5b 9d [2] 15 91 [2] 19 9b [2] 0e 90 [2] 15 de [2] 28 }

  condition:
    any of them
}