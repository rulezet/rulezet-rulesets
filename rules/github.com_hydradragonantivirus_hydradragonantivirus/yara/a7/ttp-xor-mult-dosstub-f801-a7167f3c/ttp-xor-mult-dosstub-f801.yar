rule TTP_XOR_MULT_DOSStub_f801 {
  strings:
    $key_f801 = { ac 69 [2] d8 71 [2] 9f 73 [2] d8 62 [2] 96 6e [2] 9a 64 [2] 8d 6f [2] 96 21 [2] ab }

  condition:
    any of them
}