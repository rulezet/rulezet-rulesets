rule TTP_XOR_MULT_DOSStub_195d {
  strings:
    $key_195d = { 4d 35 [2] 39 2d [2] 7e 2f [2] 39 3e [2] 77 32 [2] 7b 38 [2] 6c 33 [2] 77 7d [2] 4a }

  condition:
    any of them
}