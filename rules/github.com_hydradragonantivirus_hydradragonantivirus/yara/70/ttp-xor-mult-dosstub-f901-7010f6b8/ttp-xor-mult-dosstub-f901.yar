rule TTP_XOR_MULT_DOSStub_f901 {
  strings:
    $key_f901 = { ad 69 [2] d9 71 [2] 9e 73 [2] d9 62 [2] 97 6e [2] 9b 64 [2] 8c 6f [2] 97 21 [2] aa }

  condition:
    any of them
}