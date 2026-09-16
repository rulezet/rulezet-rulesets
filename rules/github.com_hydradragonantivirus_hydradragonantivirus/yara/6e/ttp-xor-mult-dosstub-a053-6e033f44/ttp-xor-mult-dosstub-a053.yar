rule TTP_XOR_MULT_DOSStub_a053 {
  strings:
    $key_a053 = { f4 3b [2] 80 23 [2] c7 21 [2] 80 30 [2] ce 3c [2] c2 36 [2] d5 3d [2] ce 73 [2] f3 }

  condition:
    any of them
}