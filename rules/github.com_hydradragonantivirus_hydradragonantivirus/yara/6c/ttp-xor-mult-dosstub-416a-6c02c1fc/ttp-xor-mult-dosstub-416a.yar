rule TTP_XOR_MULT_DOSStub_416a {
  strings:
    $key_416a = { 15 02 [2] 61 1a [2] 26 18 [2] 61 09 [2] 2f 05 [2] 23 0f [2] 34 04 [2] 2f 4a [2] 12 }

  condition:
    any of them
}