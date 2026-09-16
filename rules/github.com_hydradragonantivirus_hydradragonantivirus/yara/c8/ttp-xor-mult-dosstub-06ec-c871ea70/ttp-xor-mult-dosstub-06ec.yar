rule TTP_XOR_MULT_DOSStub_06ec {
  strings:
    $key_06ec = { 52 84 [2] 26 9c [2] 61 9e [2] 26 8f [2] 68 83 [2] 64 89 [2] 73 82 [2] 68 cc [2] 55 }

  condition:
    any of them
}