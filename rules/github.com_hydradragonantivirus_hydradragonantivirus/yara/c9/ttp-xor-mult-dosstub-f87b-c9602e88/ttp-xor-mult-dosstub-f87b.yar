rule TTP_XOR_MULT_DOSStub_f87b {
  strings:
    $key_f87b = { ac 13 [2] d8 0b [2] 9f 09 [2] d8 18 [2] 96 14 [2] 9a 1e [2] 8d 15 [2] 96 5b [2] ab }

  condition:
    any of them
}