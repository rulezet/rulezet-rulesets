rule TTP_XOR_MULT_DOSStub_173b {
  strings:
    $key_173b = { 43 53 [2] 37 4b [2] 70 49 [2] 37 58 [2] 79 54 [2] 75 5e [2] 62 55 [2] 79 1b [2] 44 }

  condition:
    any of them
}