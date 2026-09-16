rule TTP_XOR_MULT_DOSStub_650f {
  strings:
    $key_650f = { 31 67 [2] 45 7f [2] 02 7d [2] 45 6c [2] 0b 60 [2] 07 6a [2] 10 61 [2] 0b 2f [2] 36 }

  condition:
    any of them
}