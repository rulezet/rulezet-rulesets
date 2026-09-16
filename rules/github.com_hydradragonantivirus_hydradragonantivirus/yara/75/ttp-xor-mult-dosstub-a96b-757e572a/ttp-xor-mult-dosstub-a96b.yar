rule TTP_XOR_MULT_DOSStub_a96b {
  strings:
    $key_a96b = { fd 03 [2] 89 1b [2] ce 19 [2] 89 08 [2] c7 04 [2] cb 0e [2] dc 05 [2] c7 4b [2] fa }

  condition:
    any of them
}