rule TTP_XOR_MULT_DOSStub_fc03 {
  strings:
    $key_fc03 = { a8 6b [2] dc 73 [2] 9b 71 [2] dc 60 [2] 92 6c [2] 9e 66 [2] 89 6d [2] 92 23 [2] af }

  condition:
    any of them
}