rule TTP_XOR_MULT_DOSStub_d70c {
  strings:
    $key_d70c = { 83 64 [2] f7 7c [2] b0 7e [2] f7 6f [2] b9 63 [2] b5 69 [2] a2 62 [2] b9 2c [2] 84 }

  condition:
    any of them
}