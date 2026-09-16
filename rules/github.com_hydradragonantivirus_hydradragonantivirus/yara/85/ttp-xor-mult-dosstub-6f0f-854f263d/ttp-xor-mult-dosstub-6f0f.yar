rule TTP_XOR_MULT_DOSStub_6f0f {
  strings:
    $key_6f0f = { 3b 67 [2] 4f 7f [2] 08 7d [2] 4f 6c [2] 01 60 [2] 0d 6a [2] 1a 61 [2] 01 2f [2] 3c }

  condition:
    any of them
}