rule TTP_XOR_MULT_DOSStub_34ed {
  strings:
    $key_34ed = { 60 85 [2] 14 9d [2] 53 9f [2] 14 8e [2] 5a 82 [2] 56 88 [2] 41 83 [2] 5a cd [2] 67 }

  condition:
    any of them
}