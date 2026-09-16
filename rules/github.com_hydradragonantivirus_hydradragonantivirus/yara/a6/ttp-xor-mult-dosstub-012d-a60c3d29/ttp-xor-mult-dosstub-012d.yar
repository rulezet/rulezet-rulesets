rule TTP_XOR_MULT_DOSStub_012d {
  strings:
    $key_012d = { 55 45 [2] 21 5d [2] 66 5f [2] 21 4e [2] 6f 42 [2] 63 48 [2] 74 43 [2] 6f 0d [2] 52 }

  condition:
    any of them
}