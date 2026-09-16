rule TTP_XOR_MULT_DOSStub_ffb9 {
  strings:
    $key_ffb9 = { ab d1 [2] df c9 [2] 98 cb [2] df da [2] 91 d6 [2] 9d dc [2] 8a d7 [2] 91 99 [2] ac }

  condition:
    any of them
}