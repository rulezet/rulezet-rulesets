rule TTP_XOR_MULT_DOSStub_323c {
  strings:
    $key_323c = { 66 54 [2] 12 4c [2] 55 4e [2] 12 5f [2] 5c 53 [2] 50 59 [2] 47 52 [2] 5c 1c [2] 61 }

  condition:
    any of them
}