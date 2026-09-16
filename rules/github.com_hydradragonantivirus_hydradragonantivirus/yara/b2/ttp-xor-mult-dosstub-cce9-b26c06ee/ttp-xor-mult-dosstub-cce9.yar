rule TTP_XOR_MULT_DOSStub_cce9 {
  strings:
    $key_cce9 = { 98 81 [2] ec 99 [2] ab 9b [2] ec 8a [2] a2 86 [2] ae 8c [2] b9 87 [2] a2 c9 [2] 9f }

  condition:
    any of them
}