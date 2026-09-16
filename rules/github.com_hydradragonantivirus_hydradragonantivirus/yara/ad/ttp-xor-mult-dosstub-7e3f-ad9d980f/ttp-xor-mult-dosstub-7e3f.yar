rule TTP_XOR_MULT_DOSStub_7e3f {
  strings:
    $key_7e3f = { 2a 57 [2] 5e 4f [2] 19 4d [2] 5e 5c [2] 10 50 [2] 1c 5a [2] 0b 51 [2] 10 1f [2] 2d }

  condition:
    any of them
}