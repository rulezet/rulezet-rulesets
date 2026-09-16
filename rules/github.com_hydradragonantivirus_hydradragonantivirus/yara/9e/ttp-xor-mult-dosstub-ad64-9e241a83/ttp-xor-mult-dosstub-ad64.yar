rule TTP_XOR_MULT_DOSStub_ad64 {
  strings:
    $key_ad64 = { f9 0c [2] 8d 14 [2] ca 16 [2] 8d 07 [2] c3 0b [2] cf 01 [2] d8 0a [2] c3 44 [2] fe }

  condition:
    any of them
}