rule TTP_XOR_MULT_DOSStub_6dec {
  strings:
    $key_6dec = { 39 84 [2] 4d 9c [2] 0a 9e [2] 4d 8f [2] 03 83 [2] 0f 89 [2] 18 82 [2] 03 cc [2] 3e }

  condition:
    any of them
}