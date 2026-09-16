rule TTP_XOR_MULT_DOSStub_05ec {
  strings:
    $key_05ec = { 51 84 [2] 25 9c [2] 62 9e [2] 25 8f [2] 6b 83 [2] 67 89 [2] 70 82 [2] 6b cc [2] 56 }

  condition:
    any of them
}