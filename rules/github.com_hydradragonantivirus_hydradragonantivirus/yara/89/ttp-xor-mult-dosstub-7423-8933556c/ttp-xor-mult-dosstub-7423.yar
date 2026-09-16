rule TTP_XOR_MULT_DOSStub_7423 {
  strings:
    $key_7423 = { 20 4b [2] 54 53 [2] 13 51 [2] 54 40 [2] 1a 4c [2] 16 46 [2] 01 4d [2] 1a 03 [2] 27 }

  condition:
    any of them
}