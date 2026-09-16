rule TTP_XOR_MULT_DOSStub_3f1e {
  strings:
    $key_3f1e = { 6b 76 [2] 1f 6e [2] 58 6c [2] 1f 7d [2] 51 71 [2] 5d 7b [2] 4a 70 [2] 51 3e [2] 6c }

  condition:
    any of them
}