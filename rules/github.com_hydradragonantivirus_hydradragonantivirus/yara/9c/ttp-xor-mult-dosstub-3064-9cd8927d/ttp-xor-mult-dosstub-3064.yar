rule TTP_XOR_MULT_DOSStub_3064 {
  strings:
    $key_3064 = { 64 0c [2] 10 14 [2] 57 16 [2] 10 07 [2] 5e 0b [2] 52 01 [2] 45 0a [2] 5e 44 [2] 63 }

  condition:
    any of them
}