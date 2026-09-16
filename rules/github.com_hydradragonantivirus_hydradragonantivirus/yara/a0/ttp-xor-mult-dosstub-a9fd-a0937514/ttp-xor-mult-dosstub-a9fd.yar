rule TTP_XOR_MULT_DOSStub_a9fd {
  strings:
    $key_a9fd = { fd 95 [2] 89 8d [2] ce 8f [2] 89 9e [2] c7 92 [2] cb 98 [2] dc 93 [2] c7 dd [2] fa }

  condition:
    any of them
}