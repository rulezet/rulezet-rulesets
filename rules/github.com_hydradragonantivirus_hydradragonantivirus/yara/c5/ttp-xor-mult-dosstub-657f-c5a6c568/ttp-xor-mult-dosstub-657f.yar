rule TTP_XOR_MULT_DOSStub_657f {
  strings:
    $key_657f = { 31 17 [2] 45 0f [2] 02 0d [2] 45 1c [2] 0b 10 [2] 07 1a [2] 10 11 [2] 0b 5f [2] 36 }

  condition:
    any of them
}