rule TTP_XOR_MULT_DOSStub_faae {
  strings:
    $key_faae = { ae c6 [2] da de [2] 9d dc [2] da cd [2] 94 c1 [2] 98 cb [2] 8f c0 [2] 94 8e [2] a9 }

  condition:
    any of them
}