rule TTP_XOR_MULT_DOSStub_380c {
  strings:
    $key_380c = { 6c 64 [2] 18 7c [2] 5f 7e [2] 18 6f [2] 56 63 [2] 5a 69 [2] 4d 62 [2] 56 2c [2] 6b }

  condition:
    any of them
}