rule TTP_XOR_MULT_DOSStub_f871 {
  strings:
    $key_f871 = { ac 19 [2] d8 01 [2] 9f 03 [2] d8 12 [2] 96 1e [2] 9a 14 [2] 8d 1f [2] 96 51 [2] ab }

  condition:
    any of them
}