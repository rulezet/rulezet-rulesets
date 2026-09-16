rule TTP_XOR_WriteProcessMemory_0631 {
  strings:
    $key_0631 = { 51 43 [2] 63 61 [2] 65 54 [2] 4b 54 [2] 74 48 }

  condition:
    any of them
}