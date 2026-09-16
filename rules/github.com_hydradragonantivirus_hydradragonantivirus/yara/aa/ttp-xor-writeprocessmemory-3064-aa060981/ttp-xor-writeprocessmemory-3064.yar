rule TTP_XOR_WriteProcessMemory_3064 {
  strings:
    $key_3064 = { 67 16 [2] 55 34 [2] 53 01 [2] 7d 01 [2] 42 1d }

  condition:
    any of them
}