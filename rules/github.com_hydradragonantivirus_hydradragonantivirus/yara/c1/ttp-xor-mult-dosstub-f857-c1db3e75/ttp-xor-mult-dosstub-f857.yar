rule TTP_XOR_MULT_DOSStub_f857 {
  strings:
    $key_f857 = { ac 3f [2] d8 27 [2] 9f 25 [2] d8 34 [2] 96 38 [2] 9a 32 [2] 8d 39 [2] 96 77 [2] ab }

  condition:
    any of them
}