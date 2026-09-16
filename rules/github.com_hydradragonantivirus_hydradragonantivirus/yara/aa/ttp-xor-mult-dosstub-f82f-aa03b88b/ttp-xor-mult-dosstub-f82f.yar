rule TTP_XOR_MULT_DOSStub_f82f {
  strings:
    $key_f82f = { ac 47 [2] d8 5f [2] 9f 5d [2] d8 4c [2] 96 40 [2] 9a 4a [2] 8d 41 [2] 96 0f [2] ab }

  condition:
    any of them
}