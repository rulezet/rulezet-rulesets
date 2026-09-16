rule TTP_XOR_MULT_DOSStub_adea {
  strings:
    $key_adea = { f9 82 [2] 8d 9a [2] ca 98 [2] 8d 89 [2] c3 85 [2] cf 8f [2] d8 84 [2] c3 ca [2] fe }

  condition:
    any of them
}