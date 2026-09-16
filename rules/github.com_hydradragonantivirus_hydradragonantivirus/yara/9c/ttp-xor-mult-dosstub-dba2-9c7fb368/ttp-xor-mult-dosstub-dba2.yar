rule TTP_XOR_MULT_DOSStub_dba2 {
  strings:
    $key_dba2 = { 8f ca [2] fb d2 [2] bc d0 [2] fb c1 [2] b5 cd [2] b9 c7 [2] ae cc [2] b5 82 [2] 88 }

  condition:
    any of them
}