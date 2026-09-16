rule TTP_XOR_MULT_DOSStub_4f6a {
  strings:
    $key_4f6a = { 1b 02 [2] 6f 1a [2] 28 18 [2] 6f 09 [2] 21 05 [2] 2d 0f [2] 3a 04 [2] 21 4a [2] 1c }

  condition:
    any of them
}