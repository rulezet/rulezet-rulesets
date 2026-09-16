rule TTP_XOR_MULT_DOSStub_fc6f {
  strings:
    $key_fc6f = { a8 07 [2] dc 1f [2] 9b 1d [2] dc 0c [2] 92 00 [2] 9e 0a [2] 89 01 [2] 92 4f [2] af }

  condition:
    any of them
}