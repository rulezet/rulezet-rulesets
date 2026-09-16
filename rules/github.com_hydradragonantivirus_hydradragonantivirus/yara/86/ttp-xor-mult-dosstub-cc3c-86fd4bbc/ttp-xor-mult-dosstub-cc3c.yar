rule TTP_XOR_MULT_DOSStub_cc3c {
  strings:
    $key_cc3c = { 98 54 [2] ec 4c [2] ab 4e [2] ec 5f [2] a2 53 [2] ae 59 [2] b9 52 [2] a2 1c [2] 9f }

  condition:
    any of them
}