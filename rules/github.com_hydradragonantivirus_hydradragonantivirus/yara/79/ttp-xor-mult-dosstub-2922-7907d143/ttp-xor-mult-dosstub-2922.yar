rule TTP_XOR_MULT_DOSStub_2922 {
  strings:
    $key_2922 = { 7d 4a [2] 09 52 [2] 4e 50 [2] 09 41 [2] 47 4d [2] 4b 47 [2] 5c 4c [2] 47 02 [2] 7a }

  condition:
    any of them
}