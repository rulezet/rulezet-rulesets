rule TTP_XOR_MULT_DOSStub_4cfe {
  strings:
    $key_4cfe = { 18 96 [2] 6c 8e [2] 2b 8c [2] 6c 9d [2] 22 91 [2] 2e 9b [2] 39 90 [2] 22 de [2] 1f }

  condition:
    any of them
}