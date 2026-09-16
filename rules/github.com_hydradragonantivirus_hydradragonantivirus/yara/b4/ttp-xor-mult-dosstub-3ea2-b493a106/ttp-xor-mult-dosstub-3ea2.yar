rule TTP_XOR_MULT_DOSStub_3ea2 {
  strings:
    $key_3ea2 = { 6a ca [2] 1e d2 [2] 59 d0 [2] 1e c1 [2] 50 cd [2] 5c c7 [2] 4b cc [2] 50 82 [2] 6d }

  condition:
    any of them
}