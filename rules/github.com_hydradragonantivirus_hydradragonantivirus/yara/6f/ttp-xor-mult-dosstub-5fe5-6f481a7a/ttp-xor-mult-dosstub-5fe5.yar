rule TTP_XOR_MULT_DOSStub_5fe5 {
  strings:
    $key_5fe5 = { 0b 8d [2] 7f 95 [2] 38 97 [2] 7f 86 [2] 31 8a [2] 3d 80 [2] 2a 8b [2] 31 c5 [2] 0c }

  condition:
    any of them
}