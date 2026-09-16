rule TTP_XOR_MULT_DOSStub_236a {
  strings:
    $key_236a = { 77 02 [2] 03 1a [2] 44 18 [2] 03 09 [2] 4d 05 [2] 41 0f [2] 56 04 [2] 4d 4a [2] 70 }

  condition:
    any of them
}