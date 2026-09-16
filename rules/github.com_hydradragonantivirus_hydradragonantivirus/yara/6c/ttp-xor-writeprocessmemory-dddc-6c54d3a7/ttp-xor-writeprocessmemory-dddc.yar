rule TTP_XOR_WriteProcessMemory_dddc {
  strings:
    $key_dddc = { 8a ae [2] b8 8c [2] be b9 [2] 90 b9 [2] af a5 }

  condition:
    any of them
}