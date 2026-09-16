rule TTP_XOR_MULT_DOSStub_a10c {
  strings:
    $key_a10c = { f5 64 [2] 81 7c [2] c6 7e [2] 81 6f [2] cf 63 [2] c3 69 [2] d4 62 [2] cf 2c [2] f2 }

  condition:
    any of them
}