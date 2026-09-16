rule TTP_XOR_MULT_DOSStub_e97f {
  strings:
    $key_e97f = { bd 17 [2] c9 0f [2] 8e 0d [2] c9 1c [2] 87 10 [2] 8b 1a [2] 9c 11 [2] 87 5f [2] ba }

  condition:
    any of them
}