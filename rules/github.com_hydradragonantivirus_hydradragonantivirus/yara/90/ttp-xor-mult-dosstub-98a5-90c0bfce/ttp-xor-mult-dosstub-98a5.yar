rule TTP_XOR_MULT_DOSStub_98a5 {
  strings:
    $key_98a5 = { cc cd [2] b8 d5 [2] ff d7 [2] b8 c6 [2] f6 ca [2] fa c0 [2] ed cb [2] f6 85 [2] cb }

  condition:
    any of them
}