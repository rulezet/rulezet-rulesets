rule TTP_XOR_MULT_DOSStub_0f6b {
  strings:
    $key_0f6b = { 5b 03 [2] 2f 1b [2] 68 19 [2] 2f 08 [2] 61 04 [2] 6d 0e [2] 7a 05 [2] 61 4b [2] 5c }

  condition:
    any of them
}