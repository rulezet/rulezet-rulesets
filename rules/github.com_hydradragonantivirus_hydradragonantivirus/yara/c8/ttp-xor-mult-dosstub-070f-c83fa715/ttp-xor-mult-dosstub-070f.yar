rule TTP_XOR_MULT_DOSStub_070f {
  strings:
    $key_070f = { 53 67 [2] 27 7f [2] 60 7d [2] 27 6c [2] 69 60 [2] 65 6a [2] 72 61 [2] 69 2f [2] 54 }

  condition:
    any of them
}