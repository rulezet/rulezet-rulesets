rule TTP_XOR_MULT_DOSStub_18fe {
  strings:
    $key_18fe = { 4c 96 [2] 38 8e [2] 7f 8c [2] 38 9d [2] 76 91 [2] 7a 9b [2] 6d 90 [2] 76 de [2] 4b }

  condition:
    any of them
}