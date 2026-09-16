rule TTP_XOR_MULT_DOSStub_3dfe {
  strings:
    $key_3dfe = { 69 96 [2] 1d 8e [2] 5a 8c [2] 1d 9d [2] 53 91 [2] 5f 9b [2] 48 90 [2] 53 de [2] 6e }

  condition:
    any of them
}