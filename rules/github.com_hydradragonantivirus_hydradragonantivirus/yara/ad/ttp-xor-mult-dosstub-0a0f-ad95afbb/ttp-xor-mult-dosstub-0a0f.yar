rule TTP_XOR_MULT_DOSStub_0a0f {
  strings:
    $key_0a0f = { 5e 67 [2] 2a 7f [2] 6d 7d [2] 2a 6c [2] 64 60 [2] 68 6a [2] 7f 61 [2] 64 2f [2] 59 }

  condition:
    any of them
}