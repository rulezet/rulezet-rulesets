rule TTP_XOR_MULT_DOSStub_b928 {
  strings:
    $key_b928 = { ed 40 [2] 99 58 [2] de 5a [2] 99 4b [2] d7 47 [2] db 4d [2] cc 46 [2] d7 08 [2] ea }

  condition:
    any of them
}