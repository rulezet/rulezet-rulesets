rule TTP_XOR_MULT_DOSStub_290d {
  strings:
    $key_290d = { 7d 65 [2] 09 7d [2] 4e 7f [2] 09 6e [2] 47 62 [2] 4b 68 [2] 5c 63 [2] 47 2d [2] 7a }

  condition:
    any of them
}