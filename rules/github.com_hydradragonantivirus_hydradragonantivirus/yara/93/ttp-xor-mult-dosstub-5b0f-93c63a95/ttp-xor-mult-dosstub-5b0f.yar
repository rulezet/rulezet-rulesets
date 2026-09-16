rule TTP_XOR_MULT_DOSStub_5b0f {
  strings:
    $key_5b0f = { 0f 67 [2] 7b 7f [2] 3c 7d [2] 7b 6c [2] 35 60 [2] 39 6a [2] 2e 61 [2] 35 2f [2] 08 }

  condition:
    any of them
}