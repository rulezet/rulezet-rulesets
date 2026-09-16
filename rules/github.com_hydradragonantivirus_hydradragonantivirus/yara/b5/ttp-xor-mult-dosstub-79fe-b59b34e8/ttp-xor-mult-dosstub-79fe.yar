rule TTP_XOR_MULT_DOSStub_79fe {
  strings:
    $key_79fe = { 2d 96 [2] 59 8e [2] 1e 8c [2] 59 9d [2] 17 91 [2] 1b 9b [2] 0c 90 [2] 17 de [2] 2a }

  condition:
    any of them
}