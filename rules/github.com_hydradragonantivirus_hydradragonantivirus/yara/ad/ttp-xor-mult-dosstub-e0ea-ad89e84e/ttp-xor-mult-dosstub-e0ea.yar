rule TTP_XOR_MULT_DOSStub_e0ea {
  strings:
    $key_e0ea = { b4 82 [2] c0 9a [2] 87 98 [2] c0 89 [2] 8e 85 [2] 82 8f [2] 95 84 [2] 8e ca [2] b3 }

  condition:
    any of them
}