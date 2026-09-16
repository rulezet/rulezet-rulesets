rule TTP_XOR_MULT_DOSStub_2a0f {
  strings:
    $key_2a0f = { 7e 67 [2] 0a 7f [2] 4d 7d [2] 0a 6c [2] 44 60 [2] 48 6a [2] 5f 61 [2] 44 2f [2] 79 }

  condition:
    any of them
}