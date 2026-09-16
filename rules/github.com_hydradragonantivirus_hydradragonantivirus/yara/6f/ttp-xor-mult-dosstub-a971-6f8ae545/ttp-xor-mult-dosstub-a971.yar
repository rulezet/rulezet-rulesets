rule TTP_XOR_MULT_DOSStub_a971 {
  strings:
    $key_a971 = { fd 19 [2] 89 01 [2] ce 03 [2] 89 12 [2] c7 1e [2] cb 14 [2] dc 1f [2] c7 51 [2] fa }

  condition:
    any of them
}