rule TTP_XOR_MULT_DOSStub_10fe {
  strings:
    $key_10fe = { 44 96 [2] 30 8e [2] 77 8c [2] 30 9d [2] 7e 91 [2] 72 9b [2] 65 90 [2] 7e de [2] 43 }

  condition:
    any of them
}