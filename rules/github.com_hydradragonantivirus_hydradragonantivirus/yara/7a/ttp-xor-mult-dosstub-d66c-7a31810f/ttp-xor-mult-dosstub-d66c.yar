rule TTP_XOR_MULT_DOSStub_d66c {
  strings:
    $key_d66c = { 82 04 [2] f6 1c [2] b1 1e [2] f6 0f [2] b8 03 [2] b4 09 [2] a3 02 [2] b8 4c [2] 85 }

  condition:
    any of them
}