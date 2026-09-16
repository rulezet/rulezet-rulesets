rule TTP_XOR_MULT_DOSStub_d6ed {
  strings:
    $key_d6ed = { 82 85 [2] f6 9d [2] b1 9f [2] f6 8e [2] b8 82 [2] b4 88 [2] a3 83 [2] b8 cd [2] 85 }

  condition:
    any of them
}