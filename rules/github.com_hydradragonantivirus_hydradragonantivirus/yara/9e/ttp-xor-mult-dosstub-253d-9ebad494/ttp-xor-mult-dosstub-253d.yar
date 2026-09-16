rule TTP_XOR_MULT_DOSStub_253d {
  strings:
    $key_253d = { 71 55 [2] 05 4d [2] 42 4f [2] 05 5e [2] 4b 52 [2] 47 58 [2] 50 53 [2] 4b 1d [2] 76 }

  condition:
    any of them
}