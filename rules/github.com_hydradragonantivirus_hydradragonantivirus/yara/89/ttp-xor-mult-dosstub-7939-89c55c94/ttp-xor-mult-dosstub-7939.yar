rule TTP_XOR_MULT_DOSStub_7939 {
  strings:
    $key_7939 = { 2d 51 [2] 59 49 [2] 1e 4b [2] 59 5a [2] 17 56 [2] 1b 5c [2] 0c 57 [2] 17 19 [2] 2a }

  condition:
    any of them
}