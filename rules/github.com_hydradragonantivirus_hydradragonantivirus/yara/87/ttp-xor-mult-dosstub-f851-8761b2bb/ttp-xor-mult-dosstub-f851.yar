rule TTP_XOR_MULT_DOSStub_f851 {
  strings:
    $key_f851 = { ac 39 [2] d8 21 [2] 9f 23 [2] d8 32 [2] 96 3e [2] 9a 34 [2] 8d 3f [2] 96 71 [2] ab }

  condition:
    any of them
}