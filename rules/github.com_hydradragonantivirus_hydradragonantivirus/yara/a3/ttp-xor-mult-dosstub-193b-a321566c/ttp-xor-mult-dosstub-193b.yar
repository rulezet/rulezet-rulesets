rule TTP_XOR_MULT_DOSStub_193b {
  strings:
    $key_193b = { 4d 53 [2] 39 4b [2] 7e 49 [2] 39 58 [2] 77 54 [2] 7b 5e [2] 6c 55 [2] 77 1b [2] 4a }

  condition:
    any of them
}