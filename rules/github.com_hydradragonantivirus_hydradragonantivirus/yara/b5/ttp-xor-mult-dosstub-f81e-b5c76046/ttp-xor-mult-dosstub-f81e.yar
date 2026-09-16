rule TTP_XOR_MULT_DOSStub_f81e {
  strings:
    $key_f81e = { ac 76 [2] d8 6e [2] 9f 6c [2] d8 7d [2] 96 71 [2] 9a 7b [2] 8d 70 [2] 96 3e [2] ab }

  condition:
    any of them
}