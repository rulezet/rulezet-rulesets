rule TTP_XOR_WriteProcessMemory_4373 {
  strings:
    $key_4373 = { 14 01 [2] 26 23 [2] 20 16 [2] 0e 16 [2] 31 0a }

  condition:
    any of them
}