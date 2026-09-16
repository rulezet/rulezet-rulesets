rule TTP_XOR_WriteProcessMemory_f89d {
  strings:
    $key_f89d = { af ef [2] 9d cd [2] 9b f8 [2] b5 f8 [2] 8a e4 }

  condition:
    any of them
}