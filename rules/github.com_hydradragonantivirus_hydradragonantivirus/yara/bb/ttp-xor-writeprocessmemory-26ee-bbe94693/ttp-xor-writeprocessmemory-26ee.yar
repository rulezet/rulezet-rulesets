rule TTP_XOR_WriteProcessMemory_26ee {
  strings:
    $key_26ee = { 71 9c [2] 43 be [2] 45 8b [2] 6b 8b [2] 54 97 }

  condition:
    any of them
}