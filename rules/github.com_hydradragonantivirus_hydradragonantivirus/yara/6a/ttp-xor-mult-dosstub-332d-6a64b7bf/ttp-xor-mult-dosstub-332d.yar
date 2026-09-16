rule TTP_XOR_MULT_DOSStub_332d {
  strings:
    $key_332d = { 67 45 [2] 13 5d [2] 54 5f [2] 13 4e [2] 5d 42 [2] 51 48 [2] 46 43 [2] 5d 0d [2] 60 }

  condition:
    any of them
}