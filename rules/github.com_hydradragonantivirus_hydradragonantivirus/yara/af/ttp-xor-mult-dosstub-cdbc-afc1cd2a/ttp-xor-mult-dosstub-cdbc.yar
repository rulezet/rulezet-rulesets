rule TTP_XOR_MULT_DOSStub_cdbc {
  strings:
    $key_cdbc = { 99 d4 [2] ed cc [2] aa ce [2] ed df [2] a3 d3 [2] af d9 [2] b8 d2 [2] a3 9c [2] 9e }

  condition:
    any of them
}