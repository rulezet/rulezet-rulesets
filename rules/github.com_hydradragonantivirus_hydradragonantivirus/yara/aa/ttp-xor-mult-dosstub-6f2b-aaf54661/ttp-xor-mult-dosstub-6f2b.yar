rule TTP_XOR_MULT_DOSStub_6f2b {
  strings:
    $key_6f2b = { 3b 43 [2] 4f 5b [2] 08 59 [2] 4f 48 [2] 01 44 [2] 0d 4e [2] 1a 45 [2] 01 0b [2] 3c }

  condition:
    any of them
}