rule TTP_XOR_MULT_DOSStub_196b {
  strings:
    $key_196b = { 4d 03 [2] 39 1b [2] 7e 19 [2] 39 08 [2] 77 04 [2] 7b 0e [2] 6c 05 [2] 77 4b [2] 4a }

  condition:
    any of them
}