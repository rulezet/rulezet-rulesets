rule TTP_XOR_MULT_DOSStub_fe6c {
  strings:
    $key_fe6c = { aa 04 [2] de 1c [2] 99 1e [2] de 0f [2] 90 03 [2] 9c 09 [2] 8b 02 [2] 90 4c [2] ad }

  condition:
    any of them
}