rule TTP_XOR_MULT_DOSStub_6dad {
  strings:
    $key_6dad = { 39 c5 [2] 4d dd [2] 0a df [2] 4d ce [2] 03 c2 [2] 0f c8 [2] 18 c3 [2] 03 8d [2] 3e }

  condition:
    any of them
}