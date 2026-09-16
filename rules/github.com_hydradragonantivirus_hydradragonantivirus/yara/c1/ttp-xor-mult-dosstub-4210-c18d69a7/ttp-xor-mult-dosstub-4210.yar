rule TTP_XOR_MULT_DOSStub_4210 {
  strings:
    $key_4210 = { 16 78 [2] 62 60 [2] 25 62 [2] 62 73 [2] 2c 7f [2] 20 75 [2] 37 7e [2] 2c 30 [2] 11 }

  condition:
    any of them
}