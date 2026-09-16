rule TTP_XOR_MULT_DOSStub_e92e {
  strings:
    $key_e92e = { bd 46 [2] c9 5e [2] 8e 5c [2] c9 4d [2] 87 41 [2] 8b 4b [2] 9c 40 [2] 87 0e [2] ba }

  condition:
    any of them
}