rule TTP_XOR_MULT_DOSStub_f874 {
  strings:
    $key_f874 = { ac 1c [2] d8 04 [2] 9f 06 [2] d8 17 [2] 96 1b [2] 9a 11 [2] 8d 1a [2] 96 54 [2] ab }

  condition:
    any of them
}