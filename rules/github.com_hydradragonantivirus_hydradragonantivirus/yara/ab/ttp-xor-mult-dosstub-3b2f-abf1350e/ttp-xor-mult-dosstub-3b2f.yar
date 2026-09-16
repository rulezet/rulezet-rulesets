rule TTP_XOR_MULT_DOSStub_3b2f {
  strings:
    $key_3b2f = { 6f 47 [2] 1b 5f [2] 5c 5d [2] 1b 4c [2] 55 40 [2] 59 4a [2] 4e 41 [2] 55 0f [2] 68 }

  condition:
    any of them
}