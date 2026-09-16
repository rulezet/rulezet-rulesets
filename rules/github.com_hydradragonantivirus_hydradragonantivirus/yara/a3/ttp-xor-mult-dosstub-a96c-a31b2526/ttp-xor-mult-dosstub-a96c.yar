rule TTP_XOR_MULT_DOSStub_a96c {
  strings:
    $key_a96c = { fd 04 [2] 89 1c [2] ce 1e [2] 89 0f [2] c7 03 [2] cb 09 [2] dc 02 [2] c7 4c [2] fa }

  condition:
    any of them
}