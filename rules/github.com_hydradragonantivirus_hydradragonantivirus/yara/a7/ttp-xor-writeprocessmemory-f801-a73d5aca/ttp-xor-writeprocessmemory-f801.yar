rule TTP_XOR_WriteProcessMemory_f801 {
  strings:
    $key_f801 = { af 73 [2] 9d 51 [2] 9b 64 [2] b5 64 [2] 8a 78 }

  condition:
    any of them
}