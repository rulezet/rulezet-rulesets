rule TTP_XOR_MULT_DOSStub_7969 {
  strings:
    $key_7969 = { 2d 01 [2] 59 19 [2] 1e 1b [2] 59 0a [2] 17 06 [2] 1b 0c [2] 0c 07 [2] 17 49 [2] 2a }

  condition:
    any of them
}