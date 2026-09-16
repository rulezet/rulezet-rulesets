rule TTP_XOR_MULT_DOSStub_cc3f {
  strings:
    $key_cc3f = { 98 57 [2] ec 4f [2] ab 4d [2] ec 5c [2] a2 50 [2] ae 5a [2] b9 51 [2] a2 1f [2] 9f }

  condition:
    any of them
}