rule TTP_XOR_MULT_DOSStub_e93f {
  strings:
    $key_e93f = { bd 57 [2] c9 4f [2] 8e 4d [2] c9 5c [2] 87 50 [2] 8b 5a [2] 9c 51 [2] 87 1f [2] ba }

  condition:
    any of them
}