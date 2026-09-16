rule TTP_XOR_MULT_DOSStub_eaae {
  strings:
    $key_eaae = { be c6 [2] ca de [2] 8d dc [2] ca cd [2] 84 c1 [2] 88 cb [2] 9f c0 [2] 84 8e [2] b9 }

  condition:
    any of them
}