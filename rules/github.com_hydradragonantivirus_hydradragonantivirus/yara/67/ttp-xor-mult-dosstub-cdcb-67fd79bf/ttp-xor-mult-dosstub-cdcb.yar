rule TTP_XOR_MULT_DOSStub_cdcb {
  strings:
    $key_cdcb = { 99 a3 [2] ed bb [2] aa b9 [2] ed a8 [2] a3 a4 [2] af ae [2] b8 a5 [2] a3 eb [2] 9e }

  condition:
    any of them
}