rule TTP_XOR_MULT_DOSStub_e91f {
  strings:
    $key_e91f = { bd 77 [2] c9 6f [2] 8e 6d [2] c9 7c [2] 87 70 [2] 8b 7a [2] 9c 71 [2] 87 3f [2] ba }

  condition:
    any of them
}