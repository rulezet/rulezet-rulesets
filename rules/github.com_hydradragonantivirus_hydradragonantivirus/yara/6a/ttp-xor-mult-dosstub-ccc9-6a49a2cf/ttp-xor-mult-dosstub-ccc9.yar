rule TTP_XOR_MULT_DOSStub_ccc9 {
  strings:
    $key_ccc9 = { 98 a1 [2] ec b9 [2] ab bb [2] ec aa [2] a2 a6 [2] ae ac [2] b9 a7 [2] a2 e9 [2] 9f }

  condition:
    any of them
}