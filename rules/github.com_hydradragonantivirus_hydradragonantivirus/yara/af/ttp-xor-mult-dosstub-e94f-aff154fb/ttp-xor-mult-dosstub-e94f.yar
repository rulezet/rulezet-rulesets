rule TTP_XOR_MULT_DOSStub_e94f {
  strings:
    $key_e94f = { bd 27 [2] c9 3f [2] 8e 3d [2] c9 2c [2] 87 20 [2] 8b 2a [2] 9c 21 [2] 87 6f [2] ba }

  condition:
    any of them
}