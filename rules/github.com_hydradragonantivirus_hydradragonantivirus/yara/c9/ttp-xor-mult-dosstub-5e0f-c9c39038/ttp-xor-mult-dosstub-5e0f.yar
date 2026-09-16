rule TTP_XOR_MULT_DOSStub_5e0f {
  strings:
    $key_5e0f = { 0a 67 [2] 7e 7f [2] 39 7d [2] 7e 6c [2] 30 60 [2] 3c 6a [2] 2b 61 [2] 30 2f [2] 0d }

  condition:
    any of them
}