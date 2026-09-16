rule TTP_XOR_MULT_DOSStub_1ead {
  strings:
    $key_1ead = { 4a c5 [2] 3e dd [2] 79 df [2] 3e ce [2] 70 c2 [2] 7c c8 [2] 6b c3 [2] 70 8d [2] 4d }

  condition:
    any of them
}