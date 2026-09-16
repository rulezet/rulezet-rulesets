rule TTP_XOR_MULT_DOSStub_6dfe {
  strings:
    $key_6dfe = { 39 96 [2] 4d 8e [2] 0a 8c [2] 4d 9d [2] 03 91 [2] 0f 9b [2] 18 90 [2] 03 de [2] 3e }

  condition:
    any of them
}