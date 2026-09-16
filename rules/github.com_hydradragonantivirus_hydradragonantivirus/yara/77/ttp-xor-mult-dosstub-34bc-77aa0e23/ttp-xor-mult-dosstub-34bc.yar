rule TTP_XOR_MULT_DOSStub_34bc {
  strings:
    $key_34bc = { 60 d4 [2] 14 cc [2] 53 ce [2] 14 df [2] 5a d3 [2] 56 d9 [2] 41 d2 [2] 5a 9c [2] 67 }

  condition:
    any of them
}