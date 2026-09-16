rule TTP_XOR_MULT_DOSStub_7e2f {
  strings:
    $key_7e2f = { 2a 47 [2] 5e 5f [2] 19 5d [2] 5e 4c [2] 10 40 [2] 1c 4a [2] 0b 41 [2] 10 0f [2] 2d }

  condition:
    any of them
}