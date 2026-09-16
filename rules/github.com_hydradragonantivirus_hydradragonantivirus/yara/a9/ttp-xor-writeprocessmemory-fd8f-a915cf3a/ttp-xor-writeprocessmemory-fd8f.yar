rule TTP_XOR_WriteProcessMemory_fd8f {
  strings:
    $key_fd8f = { aa fd [2] 98 df [2] 9e ea [2] b0 ea [2] 8f f6 }

  condition:
    any of them
}