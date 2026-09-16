rule TTP_XOR_MULT_DOSStub_83ed {
  strings:
    $key_83ed = { d7 85 [2] a3 9d [2] e4 9f [2] a3 8e [2] ed 82 [2] e1 88 [2] f6 83 [2] ed cd [2] d0 }

  condition:
    any of them
}