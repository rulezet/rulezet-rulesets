rule TTP_XOR_MULT_DOSStub_f80f {
  strings:
    $key_f80f = { ac 67 [2] d8 7f [2] 9f 7d [2] d8 6c [2] 96 60 [2] 9a 6a [2] 8d 61 [2] 96 2f [2] ab }

  condition:
    any of them
}