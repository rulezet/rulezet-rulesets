rule TTP_XOR_MULT_DOSStub_e229 {
  strings:
    $key_e229 = { b6 41 [2] c2 59 [2] 85 5b [2] c2 4a [2] 8c 46 [2] 80 4c [2] 97 47 [2] 8c 09 [2] b1 }

  condition:
    any of them
}