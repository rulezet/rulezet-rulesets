rule TTP_XOR_MULT_DOSStub_472f {
  strings:
    $key_472f = { 13 47 [2] 67 5f [2] 20 5d [2] 67 4c [2] 29 40 [2] 25 4a [2] 32 41 [2] 29 0f [2] 14 }

  condition:
    any of them
}