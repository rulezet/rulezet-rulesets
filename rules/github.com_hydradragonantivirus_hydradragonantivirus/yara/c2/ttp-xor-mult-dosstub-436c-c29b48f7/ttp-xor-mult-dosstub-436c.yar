rule TTP_XOR_MULT_DOSStub_436c {
  strings:
    $key_436c = { 17 04 [2] 63 1c [2] 24 1e [2] 63 0f [2] 2d 03 [2] 21 09 [2] 36 02 [2] 2d 4c [2] 10 }

  condition:
    any of them
}