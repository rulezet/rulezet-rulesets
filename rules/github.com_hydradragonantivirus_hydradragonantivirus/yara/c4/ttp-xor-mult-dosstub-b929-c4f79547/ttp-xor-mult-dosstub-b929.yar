rule TTP_XOR_MULT_DOSStub_b929 {
  strings:
    $key_b929 = { ed 41 [2] 99 59 [2] de 5b [2] 99 4a [2] d7 46 [2] db 4c [2] cc 47 [2] d7 09 [2] ea }

  condition:
    any of them
}