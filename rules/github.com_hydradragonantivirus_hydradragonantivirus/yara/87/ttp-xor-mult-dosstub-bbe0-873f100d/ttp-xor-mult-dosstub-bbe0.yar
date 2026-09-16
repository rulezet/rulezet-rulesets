rule TTP_XOR_MULT_DOSStub_bbe0 {
  strings:
    $key_bbe0 = { ef 88 [2] 9b 90 [2] dc 92 [2] 9b 83 [2] d5 8f [2] d9 85 [2] ce 8e [2] d5 c0 [2] e8 }

  condition:
    any of them
}