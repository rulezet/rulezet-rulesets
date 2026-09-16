rule TTP_XOR_MULT_DOSStub_cc2f {
  strings:
    $key_cc2f = { 98 47 [2] ec 5f [2] ab 5d [2] ec 4c [2] a2 40 [2] ae 4a [2] b9 41 [2] a2 0f [2] 9f }

  condition:
    any of them
}