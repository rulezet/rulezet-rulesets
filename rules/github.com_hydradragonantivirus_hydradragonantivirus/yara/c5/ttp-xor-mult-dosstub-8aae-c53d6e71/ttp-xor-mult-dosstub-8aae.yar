rule TTP_XOR_MULT_DOSStub_8aae {
  strings:
    $key_8aae = { de c6 [2] aa de [2] ed dc [2] aa cd [2] e4 c1 [2] e8 cb [2] ff c0 [2] e4 8e [2] d9 }

  condition:
    any of them
}