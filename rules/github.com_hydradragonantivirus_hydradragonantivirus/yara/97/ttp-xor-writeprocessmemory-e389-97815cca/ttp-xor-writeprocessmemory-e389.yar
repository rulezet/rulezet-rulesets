rule TTP_XOR_WriteProcessMemory_e389 {
  strings:
    $key_e389 = { b4 fb [2] 86 d9 [2] 80 ec [2] ae ec [2] 91 f0 }

  condition:
    any of them
}