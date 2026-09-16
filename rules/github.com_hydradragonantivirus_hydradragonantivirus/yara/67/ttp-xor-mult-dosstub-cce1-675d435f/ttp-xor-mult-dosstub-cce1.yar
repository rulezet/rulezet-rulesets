rule TTP_XOR_MULT_DOSStub_cce1 {
  strings:
    $key_cce1 = { 98 89 [2] ec 91 [2] ab 93 [2] ec 82 [2] a2 8e [2] ae 84 [2] b9 8f [2] a2 c1 [2] 9f }

  condition:
    any of them
}