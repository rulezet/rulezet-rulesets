rule TTP_XOR_MULT_DOSStub_7cfe {
  strings:
    $key_7cfe = { 28 96 [2] 5c 8e [2] 1b 8c [2] 5c 9d [2] 12 91 [2] 1e 9b [2] 09 90 [2] 12 de [2] 2f }

  condition:
    any of them
}