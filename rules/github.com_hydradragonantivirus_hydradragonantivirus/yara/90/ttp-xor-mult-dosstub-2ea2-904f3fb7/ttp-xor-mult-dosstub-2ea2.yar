rule TTP_XOR_MULT_DOSStub_2ea2 {
  strings:
    $key_2ea2 = { 7a ca [2] 0e d2 [2] 49 d0 [2] 0e c1 [2] 40 cd [2] 4c c7 [2] 5b cc [2] 40 82 [2] 7d }

  condition:
    any of them
}