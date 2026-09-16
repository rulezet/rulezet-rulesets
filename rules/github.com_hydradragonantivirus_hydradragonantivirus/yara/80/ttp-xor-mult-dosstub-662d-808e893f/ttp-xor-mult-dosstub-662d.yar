rule TTP_XOR_MULT_DOSStub_662d {
  strings:
    $key_662d = { 32 45 [2] 46 5d [2] 01 5f [2] 46 4e [2] 08 42 [2] 04 48 [2] 13 43 [2] 08 0d [2] 35 }

  condition:
    any of them
}