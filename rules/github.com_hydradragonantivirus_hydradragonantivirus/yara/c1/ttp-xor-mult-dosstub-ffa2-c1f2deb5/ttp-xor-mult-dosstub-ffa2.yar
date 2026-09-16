rule TTP_XOR_MULT_DOSStub_ffa2 {
  strings:
    $key_ffa2 = { ab ca [2] df d2 [2] 98 d0 [2] df c1 [2] 91 cd [2] 9d c7 [2] 8a cc [2] 91 82 [2] ac }

  condition:
    any of them
}