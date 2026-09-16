rule TTP_XOR_MULT_DOSStub_ccdc {
  strings:
    $key_ccdc = { 98 b4 [2] ec ac [2] ab ae [2] ec bf [2] a2 b3 [2] ae b9 [2] b9 b2 [2] a2 fc [2] 9f }

  condition:
    any of them
}