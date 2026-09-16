rule TTP_XOR_MULT_DOSStub_2b7f {
  strings:
    $key_2b7f = { 7f 17 [2] 0b 0f [2] 4c 0d [2] 0b 1c [2] 45 10 [2] 49 1a [2] 5e 11 [2] 45 5f [2] 78 }

  condition:
    any of them
}