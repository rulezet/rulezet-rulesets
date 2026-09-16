rule TTP_XOR_MULT_DOSStub_cc7f {
  strings:
    $key_cc7f = { 98 17 [2] ec 0f [2] ab 0d [2] ec 1c [2] a2 10 [2] ae 1a [2] b9 11 [2] a2 5f [2] 9f }

  condition:
    any of them
}