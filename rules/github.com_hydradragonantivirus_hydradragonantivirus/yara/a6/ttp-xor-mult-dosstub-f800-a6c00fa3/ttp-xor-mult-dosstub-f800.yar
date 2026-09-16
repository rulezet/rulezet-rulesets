rule TTP_XOR_MULT_DOSStub_f800 {
  strings:
    $key_f800 = { ac 68 [2] d8 70 [2] 9f 72 [2] d8 63 [2] 96 6f [2] 9a 65 [2] 8d 6e [2] 96 20 [2] ab }

  condition:
    any of them
}