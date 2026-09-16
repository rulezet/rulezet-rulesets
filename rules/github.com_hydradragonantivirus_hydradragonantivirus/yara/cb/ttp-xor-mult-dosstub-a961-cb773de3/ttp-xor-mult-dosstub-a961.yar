rule TTP_XOR_MULT_DOSStub_a961 {
  strings:
    $key_a961 = { fd 09 [2] 89 11 [2] ce 13 [2] 89 02 [2] c7 0e [2] cb 04 [2] dc 0f [2] c7 41 [2] fa }

  condition:
    any of them
}