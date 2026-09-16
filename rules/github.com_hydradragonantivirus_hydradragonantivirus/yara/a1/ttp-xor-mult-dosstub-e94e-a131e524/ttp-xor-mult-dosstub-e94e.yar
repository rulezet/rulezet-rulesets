rule TTP_XOR_MULT_DOSStub_e94e {
  strings:
    $key_e94e = { bd 26 [2] c9 3e [2] 8e 3c [2] c9 2d [2] 87 21 [2] 8b 2b [2] 9c 20 [2] 87 6e [2] ba }

  condition:
    any of them
}