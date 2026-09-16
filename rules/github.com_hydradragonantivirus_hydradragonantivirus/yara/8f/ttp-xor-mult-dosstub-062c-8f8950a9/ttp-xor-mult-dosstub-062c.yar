rule TTP_XOR_MULT_DOSStub_062c {
  strings:
    $key_062c = { 52 44 [2] 26 5c [2] 61 5e [2] 26 4f [2] 68 43 [2] 64 49 [2] 73 42 [2] 68 0c [2] 55 }

  condition:
    any of them
}