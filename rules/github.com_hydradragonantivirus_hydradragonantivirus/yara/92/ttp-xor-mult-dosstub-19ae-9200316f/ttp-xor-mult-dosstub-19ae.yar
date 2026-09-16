rule TTP_XOR_MULT_DOSStub_19ae {
  strings:
    $key_19ae = { 4d c6 [2] 39 de [2] 7e dc [2] 39 cd [2] 77 c1 [2] 7b cb [2] 6c c0 [2] 77 8e [2] 4a }

  condition:
    any of them
}