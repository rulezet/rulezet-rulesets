rule TTP_XOR_MULT_DOSStub_aca5 {
  strings:
    $key_aca5 = { f8 cd [2] 8c d5 [2] cb d7 [2] 8c c6 [2] c2 ca [2] ce c0 [2] d9 cb [2] c2 85 [2] ff }

  condition:
    any of them
}