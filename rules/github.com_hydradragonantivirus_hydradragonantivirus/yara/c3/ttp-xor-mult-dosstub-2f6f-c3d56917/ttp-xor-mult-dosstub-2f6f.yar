rule TTP_XOR_MULT_DOSStub_2f6f {
  strings:
    $key_2f6f = { 7b 07 [2] 0f 1f [2] 48 1d [2] 0f 0c [2] 41 00 [2] 4d 0a [2] 5a 01 [2] 41 4f [2] 7c }

  condition:
    any of them
}