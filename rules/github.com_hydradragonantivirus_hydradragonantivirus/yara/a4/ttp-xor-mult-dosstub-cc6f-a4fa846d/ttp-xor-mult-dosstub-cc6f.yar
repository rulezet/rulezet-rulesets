rule TTP_XOR_MULT_DOSStub_cc6f {
  strings:
    $key_cc6f = { 98 07 [2] ec 1f [2] ab 1d [2] ec 0c [2] a2 00 [2] ae 0a [2] b9 01 [2] a2 4f [2] 9f }

  condition:
    any of them
}