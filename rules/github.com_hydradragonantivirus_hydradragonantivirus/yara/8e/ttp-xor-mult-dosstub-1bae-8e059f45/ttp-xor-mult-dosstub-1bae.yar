rule TTP_XOR_MULT_DOSStub_1bae {
  strings:
    $key_1bae = { 4f c6 [2] 3b de [2] 7c dc [2] 3b cd [2] 75 c1 [2] 79 cb [2] 6e c0 [2] 75 8e [2] 48 }

  condition:
    any of them
}