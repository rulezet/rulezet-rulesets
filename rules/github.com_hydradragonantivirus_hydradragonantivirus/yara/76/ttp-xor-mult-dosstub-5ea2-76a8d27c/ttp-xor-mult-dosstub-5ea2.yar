rule TTP_XOR_MULT_DOSStub_5ea2 {
  strings:
    $key_5ea2 = { 0a ca [2] 7e d2 [2] 39 d0 [2] 7e c1 [2] 30 cd [2] 3c c7 [2] 2b cc [2] 30 82 [2] 0d }

  condition:
    any of them
}