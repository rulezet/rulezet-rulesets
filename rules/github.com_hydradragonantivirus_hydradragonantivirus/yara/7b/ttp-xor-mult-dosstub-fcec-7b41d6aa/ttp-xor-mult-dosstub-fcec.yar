rule TTP_XOR_MULT_DOSStub_fcec {
  strings:
    $key_fcec = { a8 84 [2] dc 9c [2] 9b 9e [2] dc 8f [2] 92 83 [2] 9e 89 [2] 89 82 [2] 92 cc [2] af }

  condition:
    any of them
}