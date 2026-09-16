rule TTP_XOR_MULT_DOSStub_d76b {
  strings:
    $key_d76b = { 83 03 [2] f7 1b [2] b0 19 [2] f7 08 [2] b9 04 [2] b5 0e [2] a2 05 [2] b9 4b [2] 84 }

  condition:
    any of them
}