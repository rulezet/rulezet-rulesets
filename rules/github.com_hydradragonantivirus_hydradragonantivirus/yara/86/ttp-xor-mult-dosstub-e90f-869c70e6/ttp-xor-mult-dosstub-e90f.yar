rule TTP_XOR_MULT_DOSStub_e90f {
  strings:
    $key_e90f = { bd 67 [2] c9 7f [2] 8e 7d [2] c9 6c [2] 87 60 [2] 8b 6a [2] 9c 61 [2] 87 2f [2] ba }

  condition:
    any of them
}