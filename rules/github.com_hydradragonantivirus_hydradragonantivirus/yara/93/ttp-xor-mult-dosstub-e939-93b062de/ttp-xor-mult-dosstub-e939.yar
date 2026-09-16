rule TTP_XOR_MULT_DOSStub_e939 {
  strings:
    $key_e939 = { bd 51 [2] c9 49 [2] 8e 4b [2] c9 5a [2] 87 56 [2] 8b 5c [2] 9c 57 [2] 87 19 [2] ba }

  condition:
    any of them
}