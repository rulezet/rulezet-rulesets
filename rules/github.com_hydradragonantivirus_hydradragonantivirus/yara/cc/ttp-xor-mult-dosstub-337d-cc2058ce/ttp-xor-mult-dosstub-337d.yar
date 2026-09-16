rule TTP_XOR_MULT_DOSStub_337d {
  strings:
    $key_337d = { 67 15 [2] 13 0d [2] 54 0f [2] 13 1e [2] 5d 12 [2] 51 18 [2] 46 13 [2] 5d 5d [2] 60 }

  condition:
    any of them
}