rule TTP_XOR_MULT_DOSStub_abec {
  strings:
    $key_abec = { ff 84 [2] 8b 9c [2] cc 9e [2] 8b 8f [2] c5 83 [2] c9 89 [2] de 82 [2] c5 cc [2] f8 }

  condition:
    any of them
}