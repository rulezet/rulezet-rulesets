rule TTP_XOR_MULT_DOSStub_29ed {
  strings:
    $key_29ed = { 7d 85 [2] 09 9d [2] 4e 9f [2] 09 8e [2] 47 82 [2] 4b 88 [2] 5c 83 [2] 47 cd [2] 7a }

  condition:
    any of them
}