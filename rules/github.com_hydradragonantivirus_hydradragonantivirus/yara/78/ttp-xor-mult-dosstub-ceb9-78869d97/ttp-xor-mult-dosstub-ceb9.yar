rule TTP_XOR_MULT_DOSStub_ceb9 {
  strings:
    $key_ceb9 = { 9a d1 [2] ee c9 [2] a9 cb [2] ee da [2] a0 d6 [2] ac dc [2] bb d7 [2] a0 99 [2] 9d }

  condition:
    any of them
}