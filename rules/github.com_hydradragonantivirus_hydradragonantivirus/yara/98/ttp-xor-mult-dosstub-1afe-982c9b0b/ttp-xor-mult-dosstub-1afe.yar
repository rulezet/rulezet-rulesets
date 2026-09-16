rule TTP_XOR_MULT_DOSStub_1afe {
  strings:
    $key_1afe = { 4e 96 [2] 3a 8e [2] 7d 8c [2] 3a 9d [2] 74 91 [2] 78 9b [2] 6f 90 [2] 74 de [2] 49 }

  condition:
    any of them
}