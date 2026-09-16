rule TTP_XOR_MULT_DOSStub_3f7b {
  strings:
    $key_3f7b = { 6b 13 [2] 1f 0b [2] 58 09 [2] 1f 18 [2] 51 14 [2] 5d 1e [2] 4a 15 [2] 51 5b [2] 6c }

  condition:
    any of them
}