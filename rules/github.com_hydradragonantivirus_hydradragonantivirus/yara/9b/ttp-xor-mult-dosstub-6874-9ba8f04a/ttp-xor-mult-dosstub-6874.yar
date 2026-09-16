rule TTP_XOR_MULT_DOSStub_6874 {
  strings:
    $key_6874 = { 3c 1c [2] 48 04 [2] 0f 06 [2] 48 17 [2] 06 1b [2] 0a 11 [2] 1d 1a [2] 06 54 [2] 3b }

  condition:
    any of them
}