rule TTP_XOR_MULT_DOSStub_61ec {
  strings:
    $key_61ec = { 35 84 [2] 41 9c [2] 06 9e [2] 41 8f [2] 0f 83 [2] 03 89 [2] 14 82 [2] 0f cc [2] 32 }

  condition:
    any of them
}