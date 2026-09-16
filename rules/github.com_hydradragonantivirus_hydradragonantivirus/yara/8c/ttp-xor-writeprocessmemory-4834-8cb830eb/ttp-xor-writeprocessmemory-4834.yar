rule TTP_XOR_WriteProcessMemory_4834 {
  strings:
    $key_4834 = { 1f 46 [2] 2d 64 [2] 2b 51 [2] 05 51 [2] 3a 4d }

  condition:
    any of them
}