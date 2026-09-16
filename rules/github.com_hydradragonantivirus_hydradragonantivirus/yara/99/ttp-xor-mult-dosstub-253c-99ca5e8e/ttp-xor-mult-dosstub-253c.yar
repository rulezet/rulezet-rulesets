rule TTP_XOR_MULT_DOSStub_253c {
  strings:
    $key_253c = { 71 54 [2] 05 4c [2] 42 4e [2] 05 5f [2] 4b 53 [2] 47 59 [2] 50 52 [2] 4b 1c [2] 76 }

  condition:
    any of them
}