rule TTP_XOR_MULT_DOSStub_2874 {
  strings:
    $key_2874 = { 7c 1c [2] 08 04 [2] 4f 06 [2] 08 17 [2] 46 1b [2] 4a 11 [2] 5d 1a [2] 46 54 [2] 7b }

  condition:
    any of them
}