rule TTP_XOR_QUAD_CurrentVersionRun_416d {
  strings:
    $key_416d = { 12 02 [2] 36 0c [2] 1d 20 [2] 33 02 [2] 27 19 [2] 28 03 [2] 36 1e [2] 34 1f [2] 2f 19 [2] 33 1e [2] 2f 31 }

  condition:
    any of them
}