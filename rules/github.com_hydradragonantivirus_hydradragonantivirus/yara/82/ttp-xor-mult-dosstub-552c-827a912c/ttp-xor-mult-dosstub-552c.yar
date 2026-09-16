rule TTP_XOR_MULT_DOSStub_552c {
  strings:
    $key_552c = { 01 44 [2] 75 5c [2] 32 5e [2] 75 4f [2] 3b 43 [2] 37 49 [2] 20 42 [2] 3b 0c [2] 06 }

  condition:
    any of them
}