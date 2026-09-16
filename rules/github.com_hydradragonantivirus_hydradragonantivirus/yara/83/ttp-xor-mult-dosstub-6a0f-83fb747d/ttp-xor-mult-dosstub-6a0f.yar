rule TTP_XOR_MULT_DOSStub_6a0f {
  strings:
    $key_6a0f = { 3e 67 [2] 4a 7f [2] 0d 7d [2] 4a 6c [2] 04 60 [2] 08 6a [2] 1f 61 [2] 04 2f [2] 39 }

  condition:
    any of them
}