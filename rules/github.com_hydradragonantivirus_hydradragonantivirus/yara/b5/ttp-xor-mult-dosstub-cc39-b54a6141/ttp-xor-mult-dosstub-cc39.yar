rule TTP_XOR_MULT_DOSStub_cc39 {
  strings:
    $key_cc39 = { 98 51 [2] ec 49 [2] ab 4b [2] ec 5a [2] a2 56 [2] ae 5c [2] b9 57 [2] a2 19 [2] 9f }

  condition:
    any of them
}