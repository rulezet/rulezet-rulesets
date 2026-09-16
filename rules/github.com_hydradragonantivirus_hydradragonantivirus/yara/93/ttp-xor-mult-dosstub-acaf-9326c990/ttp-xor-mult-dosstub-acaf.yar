rule TTP_XOR_MULT_DOSStub_acaf {
  strings:
    $key_acaf = { f8 c7 [2] 8c df [2] cb dd [2] 8c cc [2] c2 c0 [2] ce ca [2] d9 c1 [2] c2 8f [2] ff }

  condition:
    any of them
}