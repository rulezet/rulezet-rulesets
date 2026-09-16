rule TTP_XOR_MULT_DOSStub_97ed {
  strings:
    $key_97ed = { c3 85 [2] b7 9d [2] f0 9f [2] b7 8e [2] f9 82 [2] f5 88 [2] e2 83 [2] f9 cd [2] c4 }

  condition:
    any of them
}