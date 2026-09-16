rule TTP_XOR_MULT_DOSStub_ed21 {
  strings:
    $key_ed21 = { b9 49 [2] cd 51 [2] 8a 53 [2] cd 42 [2] 83 4e [2] 8f 44 [2] 98 4f [2] 83 01 [2] be }

  condition:
    any of them
}