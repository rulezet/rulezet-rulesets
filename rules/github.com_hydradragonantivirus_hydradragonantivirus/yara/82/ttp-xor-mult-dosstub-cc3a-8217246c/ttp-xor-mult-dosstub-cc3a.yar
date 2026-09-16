rule TTP_XOR_MULT_DOSStub_cc3a {
  strings:
    $key_cc3a = { 98 52 [2] ec 4a [2] ab 48 [2] ec 59 [2] a2 55 [2] ae 5f [2] b9 54 [2] a2 1a [2] 9f }

  condition:
    any of them
}