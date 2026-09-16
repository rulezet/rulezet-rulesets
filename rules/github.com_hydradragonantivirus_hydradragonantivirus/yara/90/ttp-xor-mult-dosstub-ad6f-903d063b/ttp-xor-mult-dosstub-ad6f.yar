rule TTP_XOR_MULT_DOSStub_ad6f {
  strings:
    $key_ad6f = { f9 07 [2] 8d 1f [2] ca 1d [2] 8d 0c [2] c3 00 [2] cf 0a [2] d8 01 [2] c3 4f [2] fe }

  condition:
    any of them
}