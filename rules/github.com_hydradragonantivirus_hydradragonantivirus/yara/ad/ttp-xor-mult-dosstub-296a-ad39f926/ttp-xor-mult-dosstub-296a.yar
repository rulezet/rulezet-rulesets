rule TTP_XOR_MULT_DOSStub_296a {
  strings:
    $key_296a = { 7d 02 [2] 09 1a [2] 4e 18 [2] 09 09 [2] 47 05 [2] 4b 0f [2] 5c 04 [2] 47 4a [2] 7a }

  condition:
    any of them
}