rule TTP_XOR_MULT_DOSStub_150f {
  strings:
    $key_150f = { 41 67 [2] 35 7f [2] 72 7d [2] 35 6c [2] 7b 60 [2] 77 6a [2] 60 61 [2] 7b 2f [2] 46 }

  condition:
    any of them
}