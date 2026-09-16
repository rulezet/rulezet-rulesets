rule TTP_XOR_MULT_DOSStub_4f7f {
  strings:
    $key_4f7f = { 1b 17 [2] 6f 0f [2] 28 0d [2] 6f 1c [2] 21 10 [2] 2d 1a [2] 3a 11 [2] 21 5f [2] 1c }

  condition:
    any of them
}