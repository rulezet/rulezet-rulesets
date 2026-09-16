rule TTP_XOR_MULT_DOSStub_377f {
  strings:
    $key_377f = { 63 17 [2] 17 0f [2] 50 0d [2] 17 1c [2] 59 10 [2] 55 1a [2] 42 11 [2] 59 5f [2] 64 }

  condition:
    any of them
}