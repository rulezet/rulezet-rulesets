rule TTP_XOR_MULT_DOSStub_192b {
  strings:
    $key_192b = { 4d 43 [2] 39 5b [2] 7e 59 [2] 39 48 [2] 77 44 [2] 7b 4e [2] 6c 45 [2] 77 0b [2] 4a }

  condition:
    any of them
}