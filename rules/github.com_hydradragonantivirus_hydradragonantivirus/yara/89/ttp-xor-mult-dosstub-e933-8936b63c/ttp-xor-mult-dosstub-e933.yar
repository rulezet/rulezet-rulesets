rule TTP_XOR_MULT_DOSStub_e933 {
  strings:
    $key_e933 = { bd 5b [2] c9 43 [2] 8e 41 [2] c9 50 [2] 87 5c [2] 8b 56 [2] 9c 5d [2] 87 13 [2] ba }

  condition:
    any of them
}