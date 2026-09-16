rule TTP_XOR_MULT_DOSStub_0e0f {
  strings:
    $key_0e0f = { 5a 67 [2] 2e 7f [2] 69 7d [2] 2e 6c [2] 60 60 [2] 6c 6a [2] 7b 61 [2] 60 2f [2] 5d }

  condition:
    any of them
}