rule TTP_XOR_MULT_DOSStub_ad0c {
  strings:
    $key_ad0c = { f9 64 [2] 8d 7c [2] ca 7e [2] 8d 6f [2] c3 63 [2] cf 69 [2] d8 62 [2] c3 2c [2] fe }

  condition:
    any of them
}