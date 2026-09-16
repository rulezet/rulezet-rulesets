rule TTP_XOR_MULT_DOSStub_ad6c {
  strings:
    $key_ad6c = { f9 04 [2] 8d 1c [2] ca 1e [2] 8d 0f [2] c3 03 [2] cf 09 [2] d8 02 [2] c3 4c [2] fe }

  condition:
    any of them
}