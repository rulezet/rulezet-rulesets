rule TTP_XOR_MULT_DOSStub_140f {
  strings:
    $key_140f = { 40 67 [2] 34 7f [2] 73 7d [2] 34 6c [2] 7a 60 [2] 76 6a [2] 61 61 [2] 7a 2f [2] 47 }

  condition:
    any of them
}