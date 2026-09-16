rule TTP_XOR_MULT_DOSStub_cdf3 {
  strings:
    $key_cdf3 = { 99 9b [2] ed 83 [2] aa 81 [2] ed 90 [2] a3 9c [2] af 96 [2] b8 9d [2] a3 d3 [2] 9e }

  condition:
    any of them
}