rule TTP_XOR_MULT_DOSStub_ac6c {
  strings:
    $key_ac6c = { f8 04 [2] 8c 1c [2] cb 1e [2] 8c 0f [2] c2 03 [2] ce 09 [2] d9 02 [2] c2 4c [2] ff }

  condition:
    any of them
}