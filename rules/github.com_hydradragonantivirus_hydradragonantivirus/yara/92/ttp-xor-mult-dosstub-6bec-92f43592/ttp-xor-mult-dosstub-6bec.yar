rule TTP_XOR_MULT_DOSStub_6bec {
  strings:
    $key_6bec = { 3f 84 [2] 4b 9c [2] 0c 9e [2] 4b 8f [2] 05 83 [2] 09 89 [2] 1e 82 [2] 05 cc [2] 38 }

  condition:
    any of them
}