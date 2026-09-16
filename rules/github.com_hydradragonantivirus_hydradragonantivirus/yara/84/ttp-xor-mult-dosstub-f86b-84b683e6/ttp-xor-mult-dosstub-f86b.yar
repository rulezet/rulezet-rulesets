rule TTP_XOR_MULT_DOSStub_f86b {
  strings:
    $key_f86b = { ac 03 [2] d8 1b [2] 9f 19 [2] d8 08 [2] 96 04 [2] 9a 0e [2] 8d 05 [2] 96 4b [2] ab }

  condition:
    any of them
}