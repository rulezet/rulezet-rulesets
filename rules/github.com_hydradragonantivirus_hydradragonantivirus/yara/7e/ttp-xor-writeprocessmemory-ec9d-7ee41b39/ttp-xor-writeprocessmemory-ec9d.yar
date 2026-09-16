rule TTP_XOR_WriteProcessMemory_ec9d {
  strings:
    $key_ec9d = { bb ef [2] 89 cd [2] 8f f8 [2] a1 f8 [2] 9e e4 }

  condition:
    any of them
}