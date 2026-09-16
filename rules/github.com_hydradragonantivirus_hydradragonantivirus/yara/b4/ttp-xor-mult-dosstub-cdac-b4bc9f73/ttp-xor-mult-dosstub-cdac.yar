rule TTP_XOR_MULT_DOSStub_cdac {
  strings:
    $key_cdac = { 99 c4 [2] ed dc [2] aa de [2] ed cf [2] a3 c3 [2] af c9 [2] b8 c2 [2] a3 8c [2] 9e }

  condition:
    any of them
}