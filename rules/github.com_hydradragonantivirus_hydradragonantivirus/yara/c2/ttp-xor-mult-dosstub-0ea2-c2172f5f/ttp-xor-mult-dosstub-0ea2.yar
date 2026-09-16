rule TTP_XOR_MULT_DOSStub_0ea2 {
  strings:
    $key_0ea2 = { 5a ca [2] 2e d2 [2] 69 d0 [2] 2e c1 [2] 60 cd [2] 6c c7 [2] 7b cc [2] 60 82 [2] 5d }

  condition:
    any of them
}