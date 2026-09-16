rule TTP_XOR_MULT_DOSStub_4f0f {
  strings:
    $key_4f0f = { 1b 67 [2] 6f 7f [2] 28 7d [2] 6f 6c [2] 21 60 [2] 2d 6a [2] 3a 61 [2] 21 2f [2] 1c }

  condition:
    any of them
}