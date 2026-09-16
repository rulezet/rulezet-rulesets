rule TTP_XOR_MULT_DOSStub_f8ea {
  strings:
    $key_f8ea = { ac 82 [2] d8 9a [2] 9f 98 [2] d8 89 [2] 96 85 [2] 9a 8f [2] 8d 84 [2] 96 ca [2] ab }

  condition:
    any of them
}