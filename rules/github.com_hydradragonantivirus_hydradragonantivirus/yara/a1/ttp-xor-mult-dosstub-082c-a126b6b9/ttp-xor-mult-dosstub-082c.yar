rule TTP_XOR_MULT_DOSStub_082c {
  strings:
    $key_082c = { 5c 44 [2] 28 5c [2] 6f 5e [2] 28 4f [2] 66 43 [2] 6a 49 [2] 7d 42 [2] 66 0c [2] 5b }

  condition:
    any of them
}