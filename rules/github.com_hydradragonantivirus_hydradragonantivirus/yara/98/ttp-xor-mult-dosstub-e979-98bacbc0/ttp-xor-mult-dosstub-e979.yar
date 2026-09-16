rule TTP_XOR_MULT_DOSStub_e979 {
  strings:
    $key_e979 = { bd 11 [2] c9 09 [2] 8e 0b [2] c9 1a [2] 87 16 [2] 8b 1c [2] 9c 17 [2] 87 59 [2] ba }

  condition:
    any of them
}