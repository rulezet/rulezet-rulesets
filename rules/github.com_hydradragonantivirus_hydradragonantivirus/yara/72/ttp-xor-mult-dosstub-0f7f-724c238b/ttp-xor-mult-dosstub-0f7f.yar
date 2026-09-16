rule TTP_XOR_MULT_DOSStub_0f7f {
  strings:
    $key_0f7f = { 5b 17 [2] 2f 0f [2] 68 0d [2] 2f 1c [2] 61 10 [2] 6d 1a [2] 7a 11 [2] 61 5f [2] 5c }

  condition:
    any of them
}