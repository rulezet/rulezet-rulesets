rule TTP_XOR_MULT_DOSStub_34ea {
  strings:
    $key_34ea = { 60 82 [2] 14 9a [2] 53 98 [2] 14 89 [2] 5a 85 [2] 56 8f [2] 41 84 [2] 5a ca [2] 67 }

  condition:
    any of them
}