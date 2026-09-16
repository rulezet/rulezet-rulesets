rule TTP_XOR_MULT_DOSStub_5bfe {
  strings:
    $key_5bfe = { 0f 96 [2] 7b 8e [2] 3c 8c [2] 7b 9d [2] 35 91 [2] 39 9b [2] 2e 90 [2] 35 de [2] 08 }

  condition:
    any of them
}