rule TTP_XOR_MULT_DOSStub_195b {
  strings:
    $key_195b = { 4d 33 [2] 39 2b [2] 7e 29 [2] 39 38 [2] 77 34 [2] 7b 3e [2] 6c 35 [2] 77 7b [2] 4a }

  condition:
    any of them
}