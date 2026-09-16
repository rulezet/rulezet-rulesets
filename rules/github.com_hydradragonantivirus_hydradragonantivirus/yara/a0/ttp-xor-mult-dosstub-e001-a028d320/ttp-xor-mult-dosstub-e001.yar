rule TTP_XOR_MULT_DOSStub_e001 {
  strings:
    $key_e001 = { b4 69 [2] c0 71 [2] 87 73 [2] c0 62 [2] 8e 6e [2] 82 64 [2] 95 6f [2] 8e 21 [2] b3 }

  condition:
    any of them
}