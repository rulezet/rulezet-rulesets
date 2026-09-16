rule TTP_XOR_WriteProcessMemory_7024 {
  strings:
    $key_7024 = { 27 56 [2] 15 74 [2] 13 41 [2] 3d 41 [2] 02 5d }

  condition:
    any of them
}