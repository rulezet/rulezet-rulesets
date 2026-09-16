rule TTP_XOR_MULT_DOSStub_346c {
  strings:
    $key_346c = { 60 04 [2] 14 1c [2] 53 1e [2] 14 0f [2] 5a 03 [2] 56 09 [2] 41 02 [2] 5a 4c [2] 67 }

  condition:
    any of them
}