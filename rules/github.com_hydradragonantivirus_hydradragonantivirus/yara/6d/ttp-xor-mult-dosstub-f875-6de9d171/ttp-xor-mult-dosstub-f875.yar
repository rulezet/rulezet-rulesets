rule TTP_XOR_MULT_DOSStub_f875 {
  strings:
    $key_f875 = { ac 1d [2] d8 05 [2] 9f 07 [2] d8 16 [2] 96 1a [2] 9a 10 [2] 8d 1b [2] 96 55 [2] ab }

  condition:
    any of them
}