rule TTP_XOR_MULT_DOSStub_7929 {
  strings:
    $key_7929 = { 2d 41 [2] 59 59 [2] 1e 5b [2] 59 4a [2] 17 46 [2] 1b 4c [2] 0c 47 [2] 17 09 [2] 2a }

  condition:
    any of them
}