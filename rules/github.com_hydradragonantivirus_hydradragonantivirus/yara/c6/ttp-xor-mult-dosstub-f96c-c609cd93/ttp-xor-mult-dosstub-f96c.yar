rule TTP_XOR_MULT_DOSStub_f96c {
  strings:
    $key_f96c = { ad 04 [2] d9 1c [2] 9e 1e [2] d9 0f [2] 97 03 [2] 9b 09 [2] 8c 02 [2] 97 4c [2] aa }

  condition:
    any of them
}