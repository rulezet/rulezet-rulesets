rule TTP_XOR_MULT_DOSStub_fc24 {
  strings:
    $key_fc24 = { a8 4c [2] dc 54 [2] 9b 56 [2] dc 47 [2] 92 4b [2] 9e 41 [2] 89 4a [2] 92 04 [2] af }

  condition:
    any of them
}