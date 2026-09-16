rule TTP_XOR_MULT_DOSStub_132d {
  strings:
    $key_132d = { 47 45 [2] 33 5d [2] 74 5f [2] 33 4e [2] 7d 42 [2] 71 48 [2] 66 43 [2] 7d 0d [2] 40 }

  condition:
    any of them
}