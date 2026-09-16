rule TTP_XOR_MULT_DOSStub_cceb {
  strings:
    $key_cceb = { 98 83 [2] ec 9b [2] ab 99 [2] ec 88 [2] a2 84 [2] ae 8e [2] b9 85 [2] a2 cb [2] 9f }

  condition:
    any of them
}