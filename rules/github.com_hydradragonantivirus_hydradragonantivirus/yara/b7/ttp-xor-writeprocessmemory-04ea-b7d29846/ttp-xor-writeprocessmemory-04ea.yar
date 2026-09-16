rule TTP_XOR_WriteProcessMemory_04ea {
  strings:
    $key_04ea = { 53 98 [2] 61 ba [2] 67 8f [2] 49 8f [2] 76 93 }

  condition:
    any of them
}