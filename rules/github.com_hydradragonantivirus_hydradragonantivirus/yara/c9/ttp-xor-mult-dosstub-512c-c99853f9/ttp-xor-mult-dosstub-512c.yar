rule TTP_XOR_MULT_DOSStub_512c {
  strings:
    $key_512c = { 05 44 [2] 71 5c [2] 36 5e [2] 71 4f [2] 3f 43 [2] 33 49 [2] 24 42 [2] 3f 0c [2] 02 }

  condition:
    any of them
}