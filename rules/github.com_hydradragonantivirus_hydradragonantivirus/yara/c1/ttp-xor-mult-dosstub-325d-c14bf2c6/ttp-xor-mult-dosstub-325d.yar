rule TTP_XOR_MULT_DOSStub_325d {
  strings:
    $key_325d = { 66 35 [2] 12 2d [2] 55 2f [2] 12 3e [2] 5c 32 [2] 50 38 [2] 47 33 [2] 5c 7d [2] 61 }

  condition:
    any of them
}