rule TTP_XOR_MULT_DOSStub_adf3 {
  strings:
    $key_adf3 = { f9 9b [2] 8d 83 [2] ca 81 [2] 8d 90 [2] c3 9c [2] cf 96 [2] d8 9d [2] c3 d3 [2] fe }

  condition:
    any of them
}