rule TTP_XOR_MULT_DOSStub_f86d {
  strings:
    $key_f86d = { ac 05 [2] d8 1d [2] 9f 1f [2] d8 0e [2] 96 02 [2] 9a 08 [2] 8d 03 [2] 96 4d [2] ab }

  condition:
    any of them
}