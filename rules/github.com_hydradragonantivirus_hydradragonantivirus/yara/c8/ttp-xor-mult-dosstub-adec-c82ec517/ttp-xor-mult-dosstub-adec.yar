rule TTP_XOR_MULT_DOSStub_adec {
  strings:
    $key_adec = { f9 84 [2] 8d 9c [2] ca 9e [2] 8d 8f [2] c3 83 [2] cf 89 [2] d8 82 [2] c3 cc [2] fe }

  condition:
    any of them
}