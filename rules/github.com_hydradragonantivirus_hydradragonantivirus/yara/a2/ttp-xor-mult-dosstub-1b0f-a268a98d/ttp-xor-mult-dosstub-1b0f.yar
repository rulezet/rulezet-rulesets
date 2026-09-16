rule TTP_XOR_MULT_DOSStub_1b0f {
  strings:
    $key_1b0f = { 4f 67 [2] 3b 7f [2] 7c 7d [2] 3b 6c [2] 75 60 [2] 79 6a [2] 6e 61 [2] 75 2f [2] 48 }

  condition:
    any of them
}