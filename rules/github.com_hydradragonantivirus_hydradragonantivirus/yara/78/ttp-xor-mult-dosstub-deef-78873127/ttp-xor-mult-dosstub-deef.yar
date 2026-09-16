rule TTP_XOR_MULT_DOSStub_deef {
  strings:
    $key_deef = { 8a 87 [2] fe 9f [2] b9 9d [2] fe 8c [2] b0 80 [2] bc 8a [2] ab 81 [2] b0 cf [2] 8d }

  condition:
    any of them
}