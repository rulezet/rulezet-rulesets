rule TTP_XOR_MULT_DOSStub_1b2f {
  strings:
    $key_1b2f = { 4f 47 [2] 3b 5f [2] 7c 5d [2] 3b 4c [2] 75 40 [2] 79 4a [2] 6e 41 [2] 75 0f [2] 48 }

  condition:
    any of them
}