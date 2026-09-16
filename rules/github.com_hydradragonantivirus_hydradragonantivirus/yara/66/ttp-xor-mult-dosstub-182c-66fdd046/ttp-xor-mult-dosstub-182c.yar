rule TTP_XOR_MULT_DOSStub_182c {
  strings:
    $key_182c = { 4c 44 [2] 38 5c [2] 7f 5e [2] 38 4f [2] 76 43 [2] 7a 49 [2] 6d 42 [2] 76 0c [2] 4b }

  condition:
    any of them
}