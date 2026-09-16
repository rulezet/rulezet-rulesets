rule TTP_XOR_MULT_DOSStub_2f75 {
  strings:
    $key_2f75 = { 7b 1d [2] 0f 05 [2] 48 07 [2] 0f 16 [2] 41 1a [2] 4d 10 [2] 5a 1b [2] 41 55 [2] 7c }

  condition:
    any of them
}