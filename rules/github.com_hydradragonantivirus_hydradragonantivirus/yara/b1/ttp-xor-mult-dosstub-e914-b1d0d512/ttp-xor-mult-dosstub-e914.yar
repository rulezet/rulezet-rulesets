rule TTP_XOR_MULT_DOSStub_e914 {
  strings:
    $key_e914 = { bd 7c [2] c9 64 [2] 8e 66 [2] c9 77 [2] 87 7b [2] 8b 71 [2] 9c 7a [2] 87 34 [2] ba }

  condition:
    any of them
}