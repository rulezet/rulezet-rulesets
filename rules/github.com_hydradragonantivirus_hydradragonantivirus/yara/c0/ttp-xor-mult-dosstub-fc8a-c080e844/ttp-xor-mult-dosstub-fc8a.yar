rule TTP_XOR_MULT_DOSStub_fc8a {
  strings:
    $key_fc8a = { a8 e2 [2] dc fa [2] 9b f8 [2] dc e9 [2] 92 e5 [2] 9e ef [2] 89 e4 [2] 92 aa [2] af }

  condition:
    any of them
}