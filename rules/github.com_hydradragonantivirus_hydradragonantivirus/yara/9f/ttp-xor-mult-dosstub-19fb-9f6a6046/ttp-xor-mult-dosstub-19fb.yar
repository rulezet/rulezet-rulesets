rule TTP_XOR_MULT_DOSStub_19fb {
  strings:
    $key_19fb = { 4d 93 [2] 39 8b [2] 7e 89 [2] 39 98 [2] 77 94 [2] 7b 9e [2] 6c 95 [2] 77 db [2] 4a }

  condition:
    any of them
}