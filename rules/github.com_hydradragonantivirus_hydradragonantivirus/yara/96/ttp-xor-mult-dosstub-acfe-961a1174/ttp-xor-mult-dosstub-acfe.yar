rule TTP_XOR_MULT_DOSStub_acfe {
  strings:
    $key_acfe = { f8 96 [2] 8c 8e [2] cb 8c [2] 8c 9d [2] c2 91 [2] ce 9b [2] d9 90 [2] c2 de [2] ff }

  condition:
    any of them
}