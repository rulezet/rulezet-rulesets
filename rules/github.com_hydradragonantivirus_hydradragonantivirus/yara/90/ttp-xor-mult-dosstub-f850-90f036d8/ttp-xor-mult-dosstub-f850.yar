rule TTP_XOR_MULT_DOSStub_f850 {
  strings:
    $key_f850 = { ac 38 [2] d8 20 [2] 9f 22 [2] d8 33 [2] 96 3f [2] 9a 35 [2] 8d 3e [2] 96 70 [2] ab }

  condition:
    any of them
}