rule TTP_XOR_MULT_DOSStub_475f {
  strings:
    $key_475f = { 13 37 [2] 67 2f [2] 20 2d [2] 67 3c [2] 29 30 [2] 25 3a [2] 32 31 [2] 29 7f [2] 14 }

  condition:
    any of them
}