rule TTP_XOR_WriteProcessMemory_416c {
  strings:
    $key_416c = { 16 1e [2] 24 3c [2] 22 09 [2] 0c 09 [2] 33 15 }

  condition:
    any of them
}