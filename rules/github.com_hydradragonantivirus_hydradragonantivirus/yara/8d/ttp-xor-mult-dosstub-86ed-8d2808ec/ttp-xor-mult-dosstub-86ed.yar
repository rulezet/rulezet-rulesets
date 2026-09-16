rule TTP_XOR_MULT_DOSStub_86ed {
  strings:
    $key_86ed = { d2 85 [2] a6 9d [2] e1 9f [2] a6 8e [2] e8 82 [2] e4 88 [2] f3 83 [2] e8 cd [2] d5 }

  condition:
    any of them
}