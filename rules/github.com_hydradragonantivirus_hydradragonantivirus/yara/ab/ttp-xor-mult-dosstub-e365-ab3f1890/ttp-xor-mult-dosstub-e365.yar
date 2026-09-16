rule TTP_XOR_MULT_DOSStub_e365 {
  strings:
    $key_e365 = { b7 0d [2] c3 15 [2] 84 17 [2] c3 06 [2] 8d 0a [2] 81 00 [2] 96 0b [2] 8d 45 [2] b0 }

  condition:
    any of them
}