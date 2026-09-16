rule TTP_XOR_MULT_DOSStub_57ec {
  strings:
    $key_57ec = { 03 84 [2] 77 9c [2] 30 9e [2] 77 8f [2] 39 83 [2] 35 89 [2] 22 82 [2] 39 cc [2] 04 }

  condition:
    any of them
}