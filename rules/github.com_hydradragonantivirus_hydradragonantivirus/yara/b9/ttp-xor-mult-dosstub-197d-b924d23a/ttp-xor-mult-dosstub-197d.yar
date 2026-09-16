rule TTP_XOR_MULT_DOSStub_197d {
  strings:
    $key_197d = { 4d 15 [2] 39 0d [2] 7e 0f [2] 39 1e [2] 77 12 [2] 7b 18 [2] 6c 13 [2] 77 5d [2] 4a }

  condition:
    any of them
}