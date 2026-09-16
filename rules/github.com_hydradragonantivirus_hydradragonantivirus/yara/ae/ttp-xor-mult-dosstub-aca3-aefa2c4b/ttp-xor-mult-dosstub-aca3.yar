rule TTP_XOR_MULT_DOSStub_aca3 {
  strings:
    $key_aca3 = { f8 cb [2] 8c d3 [2] cb d1 [2] 8c c0 [2] c2 cc [2] ce c6 [2] d9 cd [2] c2 83 [2] ff }

  condition:
    any of them
}