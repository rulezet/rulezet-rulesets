rule TTP_XOR_MULT_DOSStub_8240 {
  strings:
    $key_8240 = { d6 28 [2] a2 30 [2] e5 32 [2] a2 23 [2] ec 2f [2] e0 25 [2] f7 2e [2] ec 60 [2] d1 }

  condition:
    any of them
}