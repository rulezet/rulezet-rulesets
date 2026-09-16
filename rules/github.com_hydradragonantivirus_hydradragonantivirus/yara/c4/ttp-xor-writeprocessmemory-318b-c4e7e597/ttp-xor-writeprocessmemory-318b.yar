rule TTP_XOR_WriteProcessMemory_318b {
  strings:
    $key_318b = { 66 f9 [2] 54 db [2] 52 ee [2] 7c ee [2] 43 f2 }

  condition:
    any of them
}