rule TTP_XOR_MULT_DOSStub_7d0f {
  strings:
    $key_7d0f = { 29 67 [2] 5d 7f [2] 1a 7d [2] 5d 6c [2] 13 60 [2] 1f 6a [2] 08 61 [2] 13 2f [2] 2e }

  condition:
    any of them
}