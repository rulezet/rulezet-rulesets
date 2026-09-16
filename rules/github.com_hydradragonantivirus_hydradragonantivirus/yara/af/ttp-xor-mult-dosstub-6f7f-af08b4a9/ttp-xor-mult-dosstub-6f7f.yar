rule TTP_XOR_MULT_DOSStub_6f7f {
  strings:
    $key_6f7f = { 3b 17 [2] 4f 0f [2] 08 0d [2] 4f 1c [2] 01 10 [2] 0d 1a [2] 1a 11 [2] 01 5f [2] 3c }

  condition:
    any of them
}