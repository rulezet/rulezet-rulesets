rule TTP_XOR_MULT_DOSStub_2fad {
  strings:
    $key_2fad = { 7b c5 [2] 0f dd [2] 48 df [2] 0f ce [2] 41 c2 [2] 4d c8 [2] 5a c3 [2] 41 8d [2] 7c }

  condition:
    any of them
}