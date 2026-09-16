rule TTP_XOR_MULT_DOSStub_4c0f {
  strings:
    $key_4c0f = { 18 67 [2] 6c 7f [2] 2b 7d [2] 6c 6c [2] 22 60 [2] 2e 6a [2] 39 61 [2] 22 2f [2] 1f }

  condition:
    any of them
}