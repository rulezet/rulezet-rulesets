rule TTP_XOR_MULT_DOSStub_22ea {
  strings:
    $key_22ea = { 76 82 [2] 02 9a [2] 45 98 [2] 02 89 [2] 4c 85 [2] 40 8f [2] 57 84 [2] 4c ca [2] 71 }

  condition:
    any of them
}