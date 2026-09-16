rule TTP_XOR_MULT_DOSStub_416e {
  strings:
    $key_416e = { 15 06 [2] 61 1e [2] 26 1c [2] 61 0d [2] 2f 01 [2] 23 0b [2] 34 00 [2] 2f 4e [2] 12 }

  condition:
    any of them
}