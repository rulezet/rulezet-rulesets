rule TTP_XOR_MULT_DOSStub_5f6a {
  strings:
    $key_5f6a = { 0b 02 [2] 7f 1a [2] 38 18 [2] 7f 09 [2] 31 05 [2] 3d 0f [2] 2a 04 [2] 31 4a [2] 0c }

  condition:
    any of them
}