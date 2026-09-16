rule TTP_XOR_MULT_DOSStub_613c {
  strings:
    $key_613c = { 35 54 [2] 41 4c [2] 06 4e [2] 41 5f [2] 0f 53 [2] 03 59 [2] 14 52 [2] 0f 1c [2] 32 }

  condition:
    any of them
}