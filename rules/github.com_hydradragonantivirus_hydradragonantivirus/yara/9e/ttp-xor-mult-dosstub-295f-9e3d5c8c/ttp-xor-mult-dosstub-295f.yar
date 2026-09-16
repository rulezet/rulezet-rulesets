rule TTP_XOR_MULT_DOSStub_295f {
  strings:
    $key_295f = { 7d 37 [2] 09 2f [2] 4e 2d [2] 09 3c [2] 47 30 [2] 4b 3a [2] 5c 31 [2] 47 7f [2] 7a }

  condition:
    any of them
}