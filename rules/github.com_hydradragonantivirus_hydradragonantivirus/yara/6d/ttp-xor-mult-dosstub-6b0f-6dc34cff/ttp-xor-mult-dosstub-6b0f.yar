rule TTP_XOR_MULT_DOSStub_6b0f {
  strings:
    $key_6b0f = { 3f 67 [2] 4b 7f [2] 0c 7d [2] 4b 6c [2] 05 60 [2] 09 6a [2] 1e 61 [2] 05 2f [2] 38 }

  condition:
    any of them
}