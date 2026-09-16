rule TTP_XOR_MULT_DOSStub_fcf3 {
  strings:
    $key_fcf3 = { a8 9b [2] dc 83 [2] 9b 81 [2] dc 90 [2] 92 9c [2] 9e 96 [2] 89 9d [2] 92 d3 [2] af }

  condition:
    any of them
}