rule TTP_XOR_MULT_DOSStub_e94d {
  strings:
    $key_e94d = { bd 25 [2] c9 3d [2] 8e 3f [2] c9 2e [2] 87 22 [2] 8b 28 [2] 9c 23 [2] 87 6d [2] ba }

  condition:
    any of them
}