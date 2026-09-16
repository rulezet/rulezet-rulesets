rule TTP_XOR_MULT_DOSStub_08fe {
  strings:
    $key_08fe = { 5c 96 [2] 28 8e [2] 6f 8c [2] 28 9d [2] 66 91 [2] 6a 9b [2] 7d 90 [2] 66 de [2] 5b }

  condition:
    any of them
}