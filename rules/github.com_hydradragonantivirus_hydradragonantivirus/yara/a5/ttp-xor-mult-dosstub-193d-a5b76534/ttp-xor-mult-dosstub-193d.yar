rule TTP_XOR_MULT_DOSStub_193d {
  strings:
    $key_193d = { 4d 55 [2] 39 4d [2] 7e 4f [2] 39 5e [2] 77 52 [2] 7b 58 [2] 6c 53 [2] 77 1d [2] 4a }

  condition:
    any of them
}