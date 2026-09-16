rule TTP_XOR_MULT_DOSStub_6a75 {
  strings:
    $key_6a75 = { 3e 1d [2] 4a 05 [2] 0d 07 [2] 4a 16 [2] 04 1a [2] 08 10 [2] 1f 1b [2] 04 55 [2] 39 }

  condition:
    any of them
}