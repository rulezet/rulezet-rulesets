rule TTP_XOR_WriteProcessMemory_36ee {
  strings:
    $key_36ee = { 61 9c [2] 53 be [2] 55 8b [2] 7b 8b [2] 44 97 }

  condition:
    any of them
}