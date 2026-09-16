rule TTP_XOR_MULT_DOSStub_3eff {
  strings:
    $key_3eff = { 6a 97 [2] 1e 8f [2] 59 8d [2] 1e 9c [2] 50 90 [2] 5c 9a [2] 4b 91 [2] 50 df [2] 6d }

  condition:
    any of them
}