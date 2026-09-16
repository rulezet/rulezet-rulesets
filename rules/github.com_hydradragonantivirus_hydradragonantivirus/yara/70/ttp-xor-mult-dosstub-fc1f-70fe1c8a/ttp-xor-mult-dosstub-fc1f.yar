rule TTP_XOR_MULT_DOSStub_fc1f {
  strings:
    $key_fc1f = { a8 77 [2] dc 6f [2] 9b 6d [2] dc 7c [2] 92 70 [2] 9e 7a [2] 89 71 [2] 92 3f [2] af }

  condition:
    any of them
}