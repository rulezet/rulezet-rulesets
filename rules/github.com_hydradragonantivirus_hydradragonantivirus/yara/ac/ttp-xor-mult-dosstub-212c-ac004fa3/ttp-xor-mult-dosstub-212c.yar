rule TTP_XOR_MULT_DOSStub_212c {
  strings:
    $key_212c = { 75 44 [2] 01 5c [2] 46 5e [2] 01 4f [2] 4f 43 [2] 43 49 [2] 54 42 [2] 4f 0c [2] 72 }

  condition:
    any of them
}