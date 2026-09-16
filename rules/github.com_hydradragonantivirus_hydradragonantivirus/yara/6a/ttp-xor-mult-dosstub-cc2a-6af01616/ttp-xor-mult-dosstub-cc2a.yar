rule TTP_XOR_MULT_DOSStub_cc2a {
  strings:
    $key_cc2a = { 98 42 [2] ec 5a [2] ab 58 [2] ec 49 [2] a2 45 [2] ae 4f [2] b9 44 [2] a2 0a [2] 9f }

  condition:
    any of them
}