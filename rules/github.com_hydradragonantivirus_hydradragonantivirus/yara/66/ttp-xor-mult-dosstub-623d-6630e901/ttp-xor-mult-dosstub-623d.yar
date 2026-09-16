rule TTP_XOR_MULT_DOSStub_623d {
  strings:
    $key_623d = { 36 55 [2] 42 4d [2] 05 4f [2] 42 5e [2] 0c 52 [2] 00 58 [2] 17 53 [2] 0c 1d [2] 31 }

  condition:
    any of them
}