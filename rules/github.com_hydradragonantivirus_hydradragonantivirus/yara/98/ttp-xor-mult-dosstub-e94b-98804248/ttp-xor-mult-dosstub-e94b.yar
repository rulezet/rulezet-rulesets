rule TTP_XOR_MULT_DOSStub_e94b {
  strings:
    $key_e94b = { bd 23 [2] c9 3b [2] 8e 39 [2] c9 28 [2] 87 24 [2] 8b 2e [2] 9c 25 [2] 87 6b [2] ba }

  condition:
    any of them
}