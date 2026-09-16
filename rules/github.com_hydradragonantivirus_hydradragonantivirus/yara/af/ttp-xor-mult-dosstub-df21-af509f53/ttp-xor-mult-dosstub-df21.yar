rule TTP_XOR_MULT_DOSStub_df21 {
  strings:
    $key_df21 = { 8b 49 [2] ff 51 [2] b8 53 [2] ff 42 [2] b1 4e [2] bd 44 [2] aa 4f [2] b1 01 [2] 8c }

  condition:
    any of them
}