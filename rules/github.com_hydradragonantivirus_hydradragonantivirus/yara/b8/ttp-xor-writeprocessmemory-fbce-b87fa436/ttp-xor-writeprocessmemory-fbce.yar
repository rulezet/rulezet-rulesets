rule TTP_XOR_WriteProcessMemory_fbce {
  strings:
    $key_fbce = { ac bc [2] 9e 9e [2] 98 ab [2] b6 ab [2] 89 b7 }

  condition:
    any of them
}