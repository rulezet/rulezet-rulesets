rule TTP_XOR_MULT_DOSStub_322d {
  strings:
    $key_322d = { 66 45 [2] 12 5d [2] 55 5f [2] 12 4e [2] 5c 42 [2] 50 48 [2] 47 43 [2] 5c 0d [2] 61 }

  condition:
    any of them
}