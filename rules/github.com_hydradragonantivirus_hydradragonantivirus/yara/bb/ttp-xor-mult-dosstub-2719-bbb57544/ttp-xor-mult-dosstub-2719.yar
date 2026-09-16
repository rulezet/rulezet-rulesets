rule TTP_XOR_MULT_DOSStub_2719 {
  strings:
    $key_2719 = { 73 71 [2] 07 69 [2] 40 6b [2] 07 7a [2] 49 76 [2] 45 7c [2] 52 77 [2] 49 39 [2] 74 }

  condition:
    any of them
}