rule TTP_XOR_MULT_DOSStub_6aec {
  strings:
    $key_6aec = { 3e 84 [2] 4a 9c [2] 0d 9e [2] 4a 8f [2] 04 83 [2] 08 89 [2] 1f 82 [2] 04 cc [2] 39 }

  condition:
    any of them
}