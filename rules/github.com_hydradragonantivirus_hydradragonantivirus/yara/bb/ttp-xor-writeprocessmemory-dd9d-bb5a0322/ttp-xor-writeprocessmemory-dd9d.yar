rule TTP_XOR_WriteProcessMemory_dd9d {
  strings:
    $key_dd9d = { 8a ef [2] b8 cd [2] be f8 [2] 90 f8 [2] af e4 }

  condition:
    any of them
}