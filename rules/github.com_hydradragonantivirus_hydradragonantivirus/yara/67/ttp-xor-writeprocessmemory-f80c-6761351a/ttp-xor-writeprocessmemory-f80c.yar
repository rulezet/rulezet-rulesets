rule TTP_XOR_WriteProcessMemory_f80c {
  strings:
    $key_f80c = { af 7e [2] 9d 5c [2] 9b 69 [2] b5 69 [2] 8a 75 }

  condition:
    any of them
}