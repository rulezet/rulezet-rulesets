rule TTP_XOR_MULT_DOSStub_f856 {
  strings:
    $key_f856 = { ac 3e [2] d8 26 [2] 9f 24 [2] d8 35 [2] 96 39 [2] 9a 33 [2] 8d 38 [2] 96 76 [2] ab }

  condition:
    any of them
}