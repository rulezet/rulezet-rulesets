rule TTP_XOR_MULT_DOSStub_6f7d {
  strings:
    $key_6f7d = { 3b 15 [2] 4f 0d [2] 08 0f [2] 4f 1e [2] 01 12 [2] 0d 18 [2] 1a 13 [2] 01 5d [2] 3c }

  condition:
    any of them
}