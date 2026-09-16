rule TTP_XOR_MULT_DOSStub_7174 {
  strings:
    $key_7174 = { 25 1c [2] 51 04 [2] 16 06 [2] 51 17 [2] 1f 1b [2] 13 11 [2] 04 1a [2] 1f 54 [2] 22 }

  condition:
    any of them
}