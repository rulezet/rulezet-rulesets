rule TTP_XOR_MULT_DOSStub_3bfe {
  strings:
    $key_3bfe = { 6f 96 [2] 1b 8e [2] 5c 8c [2] 1b 9d [2] 55 91 [2] 59 9b [2] 4e 90 [2] 55 de [2] 68 }

  condition:
    any of them
}