rule TTP_XOR_MULT_DOSStub_2c2f {
  strings:
    $key_2c2f = { 78 47 [2] 0c 5f [2] 4b 5d [2] 0c 4c [2] 42 40 [2] 4e 4a [2] 59 41 [2] 42 0f [2] 7f }

  condition:
    any of them
}