rule TTP_XOR_MULT_DOSStub_ccfd {
  strings:
    $key_ccfd = { 98 95 [2] ec 8d [2] ab 8f [2] ec 9e [2] a2 92 [2] ae 98 [2] b9 93 [2] a2 dd [2] 9f }

  condition:
    any of them
}