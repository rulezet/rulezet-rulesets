rule TTP_XOR_MULT_DOSStub_260f {
  strings:
    $key_260f = { 72 67 [2] 06 7f [2] 41 7d [2] 06 6c [2] 48 60 [2] 44 6a [2] 53 61 [2] 48 2f [2] 75 }

  condition:
    any of them
}