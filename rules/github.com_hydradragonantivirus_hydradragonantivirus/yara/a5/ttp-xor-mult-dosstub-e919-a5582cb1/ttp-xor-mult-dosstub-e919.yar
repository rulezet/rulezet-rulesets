rule TTP_XOR_MULT_DOSStub_e919 {
  strings:
    $key_e919 = { bd 71 [2] c9 69 [2] 8e 6b [2] c9 7a [2] 87 76 [2] 8b 7c [2] 9c 77 [2] 87 39 [2] ba }

  condition:
    any of them
}