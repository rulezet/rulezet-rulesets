rule TTP_XOR_MULT_DOSStub_0f6a {
  strings:
    $key_0f6a = { 5b 02 [2] 2f 1a [2] 68 18 [2] 2f 09 [2] 61 05 [2] 6d 0f [2] 7a 04 [2] 61 4a [2] 5c }

  condition:
    any of them
}