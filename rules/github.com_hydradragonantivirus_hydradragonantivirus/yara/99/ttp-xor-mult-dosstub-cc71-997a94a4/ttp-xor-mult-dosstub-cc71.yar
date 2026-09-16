rule TTP_XOR_MULT_DOSStub_cc71 {
  strings:
    $key_cc71 = { 98 19 [2] ec 01 [2] ab 03 [2] ec 12 [2] a2 1e [2] ae 14 [2] b9 1f [2] a2 51 [2] 9f }

  condition:
    any of them
}