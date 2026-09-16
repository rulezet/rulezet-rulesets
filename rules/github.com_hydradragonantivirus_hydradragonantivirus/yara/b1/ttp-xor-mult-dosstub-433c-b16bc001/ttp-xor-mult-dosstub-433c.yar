rule TTP_XOR_MULT_DOSStub_433c {
  strings:
    $key_433c = { 17 54 [2] 63 4c [2] 24 4e [2] 63 5f [2] 2d 53 [2] 21 59 [2] 36 52 [2] 2d 1c [2] 10 }

  condition:
    any of them
}