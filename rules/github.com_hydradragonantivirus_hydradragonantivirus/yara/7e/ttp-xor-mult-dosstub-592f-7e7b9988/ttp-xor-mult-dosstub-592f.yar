rule TTP_XOR_MULT_DOSStub_592f {
  strings:
    $key_592f = { 0d 47 [2] 79 5f [2] 3e 5d [2] 79 4c [2] 37 40 [2] 3b 4a [2] 2c 41 [2] 37 0f [2] 0a }

  condition:
    any of them
}