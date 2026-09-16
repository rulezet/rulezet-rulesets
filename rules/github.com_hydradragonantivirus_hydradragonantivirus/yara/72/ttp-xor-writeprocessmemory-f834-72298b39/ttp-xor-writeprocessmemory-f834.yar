rule TTP_XOR_WriteProcessMemory_f834 {
  strings:
    $key_f834 = { af 46 [2] 9d 64 [2] 9b 51 [2] b5 51 [2] 8a 4d }

  condition:
    any of them
}