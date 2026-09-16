rule TTP_XOR_MULT_DOSStub_2a2f {
  strings:
    $key_2a2f = { 7e 47 [2] 0a 5f [2] 4d 5d [2] 0a 4c [2] 44 40 [2] 48 4a [2] 5f 41 [2] 44 0f [2] 79 }

  condition:
    any of them
}