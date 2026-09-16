rule TTP_XOR_MULT_DOSStub_ec0f {
  strings:
    $key_ec0f = { b8 67 [2] cc 7f [2] 8b 7d [2] cc 6c [2] 82 60 [2] 8e 6a [2] 99 61 [2] 82 2f [2] bf }

  condition:
    any of them
}