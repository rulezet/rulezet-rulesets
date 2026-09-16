rule TTP_XOR_WriteProcessMemory_f823 {
  strings:
    $key_f823 = { af 51 [2] 9d 73 [2] 9b 46 [2] b5 46 [2] 8a 5a }

  condition:
    any of them
}