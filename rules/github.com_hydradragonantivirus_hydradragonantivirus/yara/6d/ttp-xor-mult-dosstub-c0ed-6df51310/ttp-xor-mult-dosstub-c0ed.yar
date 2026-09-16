rule TTP_XOR_MULT_DOSStub_c0ed {
  strings:
    $key_c0ed = { 94 85 [2] e0 9d [2] a7 9f [2] e0 8e [2] ae 82 [2] a2 88 [2] b5 83 [2] ae cd [2] 93 }

  condition:
    any of them
}