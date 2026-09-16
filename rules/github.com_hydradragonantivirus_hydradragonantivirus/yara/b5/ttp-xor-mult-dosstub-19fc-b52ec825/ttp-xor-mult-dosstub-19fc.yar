rule TTP_XOR_MULT_DOSStub_19fc {
  strings:
    $key_19fc = { 4d 94 [2] 39 8c [2] 7e 8e [2] 39 9f [2] 77 93 [2] 7b 99 [2] 6c 92 [2] 77 dc [2] 4a }

  condition:
    any of them
}