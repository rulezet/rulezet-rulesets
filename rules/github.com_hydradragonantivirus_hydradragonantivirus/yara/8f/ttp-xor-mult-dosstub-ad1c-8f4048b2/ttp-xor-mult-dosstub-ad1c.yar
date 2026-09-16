rule TTP_XOR_MULT_DOSStub_ad1c {
  strings:
    $key_ad1c = { f9 74 [2] 8d 6c [2] ca 6e [2] 8d 7f [2] c3 73 [2] cf 79 [2] d8 72 [2] c3 3c [2] fe }

  condition:
    any of them
}