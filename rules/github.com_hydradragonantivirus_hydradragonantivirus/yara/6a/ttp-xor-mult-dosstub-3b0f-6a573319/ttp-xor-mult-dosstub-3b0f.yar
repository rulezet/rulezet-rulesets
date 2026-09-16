rule TTP_XOR_MULT_DOSStub_3b0f {
  strings:
    $key_3b0f = { 6f 67 [2] 1b 7f [2] 5c 7d [2] 1b 6c [2] 55 60 [2] 59 6a [2] 4e 61 [2] 55 2f [2] 68 }

  condition:
    any of them
}