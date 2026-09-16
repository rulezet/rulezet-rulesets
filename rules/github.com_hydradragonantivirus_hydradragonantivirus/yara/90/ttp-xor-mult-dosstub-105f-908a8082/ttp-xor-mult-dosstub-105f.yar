rule TTP_XOR_MULT_DOSStub_105f {
  strings:
    $key_105f = { 44 37 [2] 30 2f [2] 77 2d [2] 30 3c [2] 7e 30 [2] 72 3a [2] 65 31 [2] 7e 7f [2] 43 }

  condition:
    any of them
}