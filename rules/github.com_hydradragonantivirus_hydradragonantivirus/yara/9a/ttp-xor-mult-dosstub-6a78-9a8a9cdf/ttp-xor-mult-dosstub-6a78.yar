rule TTP_XOR_MULT_DOSStub_6a78 {
  strings:
    $key_6a78 = { 3e 10 [2] 4a 08 [2] 0d 0a [2] 4a 1b [2] 04 17 [2] 08 1d [2] 1f 16 [2] 04 58 [2] 39 }

  condition:
    any of them
}