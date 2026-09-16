rule TTP_XOR_MULT_DOSStub_e97c {
  strings:
    $key_e97c = { bd 14 [2] c9 0c [2] 8e 0e [2] c9 1f [2] 87 13 [2] 8b 19 [2] 9c 12 [2] 87 5c [2] ba }

  condition:
    any of them
}