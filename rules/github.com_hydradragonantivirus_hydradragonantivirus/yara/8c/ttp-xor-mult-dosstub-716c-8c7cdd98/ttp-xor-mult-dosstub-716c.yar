rule TTP_XOR_MULT_DOSStub_716c {
  strings:
    $key_716c = { 25 04 [2] 51 1c [2] 16 1e [2] 51 0f [2] 1f 03 [2] 13 09 [2] 04 02 [2] 1f 4c [2] 22 }

  condition:
    any of them
}